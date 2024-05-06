<?php

namespace Juanbautista0\Signer;

use DOMDocument;
use Error;
use Exception;

final class Policy
{
    public string | null $signedXml = null;
    public string $signatureID;
    public string $reference0Id;
    public string $keyInfoId;
    public string $signedPropertiesId;

    public readonly SignerPolicy $signerPolicy;
    public readonly CertificateHandler $certificate;
    public string $unsignedXml;
    public string $doctype;

    public function __construct(SignerPolicy $signerPolicy, CertificateHandler $certificate, string $unsignedXml, string $doctype)
    {
    }



    public function Sign(string $uuid): ResultType
    {
        try {

            $tmpCertificateDate = [];

            //  validate existence and read certificate
            if (!$pfx = file_get_contents($this->certificate->path)) {
                throw new Exception("Error: Certificate file cannot be read\n", 1);
            }

            //  authentication and reading of the certificate
            openssl_pkcs12_read($pfx, $tmpCertificateDate, $this->certificate->path);

            $this->certificate->publicKey          =  $tmpCertificateDate["cert"];
            $this->certificate->privateKey         =  $tmpCertificateDate["pkey"];

            $this->signatureID        = "xmldsig-$uuid";
            $this->reference0Id       = "xmldsig-$uuid-ref0";
            $this->keyInfoId          = "xmldsig-$uuid-KeyInfo";
            $this->signedPropertiesId = "xmldsig-$uuid-signedprops";

            $result = new  ResultType();
            $result->data   = $this->insertSignature();

            return $result;
        } catch (\Throwable $th) {
            $result = new  ResultType();
            $result->error = new Error($th->getMessage());
            return $result;
        }
    }

    private function insertSignature()
    {
        //  deleting line breaks and carriage returns
        $this->unsignedXml = str_replace("\r", "", str_replace("\n", "", $this->unsignedXml));
        $this->unsignedXml = str_replace('&', '&amp;', $this->unsignedXml);

        //  canonizes the entire document for the digest

        $d = new DOMDocument('1.0', 'UTF-8');
        $d->preserveWhiteSpace = true;
        $d->loadXML($this->unsignedXml);
        $canonicalXML = $d->C14N(false, false, null, null);
        $signTime = date('Y-m-d\TH:i:s-05:00');
        $algorithmType = "SHA256";
        $documentDigest = base64_encode(hash(strtolower($algorithmType), $canonicalXML, true));


        $certData   = openssl_x509_parse($this->certificate->publicKey);
        $certDigest = base64_encode(openssl_x509_fingerprint($this->certificate->publicKey, strtolower($algorithmType), true));

        if ($this->doctype == 'nc') {
            $certSerialNumber = intval($certData['serialNumber']);
        } else {
            $certSerialNumber = $certData['serialNumber'];
        }

        $certIssuer = $this->getIssuer($certData['issuer']);

        $SignedProperties = $this->generateSignedProperties($signTime, $certDigest, $certIssuer, $certSerialNumber);
        $SignedPropertiesWithSchemas = str_replace('<xades:SignedProperties', '<xades:SignedProperties ' . $this->getSchemas(), $SignedProperties);
        $SignedPropertiesDigest =  base64_encode(hash(strtolower($algorithmType), $SignedPropertiesWithSchemas, true));

        $KeyInfo = $this->getKeyInfo();
        $keyInfoWithShemas = str_replace('<ds:KeyInfo', '<ds:KeyInfo ' . $this->getSchemas($this->doctype), $KeyInfo);

        $kInfoDigest =   base64_encode(hash(strtolower($algorithmType), $keyInfoWithShemas, true));

        $signedInfo = $this->getSignedInfo($documentDigest, $kInfoDigest, $SignedPropertiesDigest);
        $SignedInfoWithSchemas = str_replace('<ds:SignedInfo', '<ds:SignedInfo ' . $this->getSchemas($this->doctype), $signedInfo);


        openssl_sign($SignedInfoWithSchemas, $signatureResult, $this->certificate->privateKey, $algorithmType);
        $signatureResult = base64_encode($signatureResult);


        $s = '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="' . $this->signatureID . '">' . $signedInfo . '<ds:SignatureValue>' . $signatureResult . '</ds:SignatureValue>' . $KeyInfo . '<ds:Object><xades:QualifyingProperties Target="#' . $this->signatureID . '">' . $SignedProperties . '</xades:QualifyingProperties></ds:Object></ds:Signature>';


        $buscar    = '<ext:ExtensionContent></ext:ExtensionContent>';
        $remplazar = "<ext:ExtensionContent>" . $s . "</ext:ExtensionContent>";
        $pos       = strrpos($canonicalXML, $buscar);
        if ($pos !== false) {
            $this->signedXml = substr_replace($canonicalXML, $remplazar, $pos, strlen($buscar));
        }

        return $this->signedXml;
    }

    public function getIssuer($issuer): string
    {
        $certIssuer = [];

        foreach ($issuer as $item => $value) {
            $certIssuer[] = "$item=$value";
        }

        $certIssuer = implode(', ', array_reverse($certIssuer));

        return $certIssuer;
    }

    public function generateSignedProperties(string $signTime, string $certDigest, string $certIssuer, string |int $certSerialNumber)
    {

        return '<xades:SignedProperties Id="' . $this->signedPropertiesId . '">' .
            '<xades:SignedSignatureProperties>' .
            '<xades:SigningTime>' . $signTime . '</xades:SigningTime>' .
            '<xades:SigningCertificate>' .
            '<xades:Cert>' .
            '<xades:CertDigest>' .
            '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>' .
            '<ds:DigestValue>' . $certDigest . '</ds:DigestValue>' .
            '</xades:CertDigest>' .
            '<xades:IssuerSerial>' .
            '<ds:X509IssuerName>' . $certIssuer . '</ds:X509IssuerName>' .
            '<ds:X509SerialNumber>' . $certSerialNumber . '</ds:X509SerialNumber>' .
            '</xades:IssuerSerial>' .
            '</xades:Cert>' .
            '</xades:SigningCertificate>' .
            '<xades:SignaturePolicyIdentifier>' .
            '<xades:SignaturePolicyId>' .
            '<xades:SigPolicyId>' .
            '<xades:Identifier>' . $this->signerPolicy->url . '</xades:Identifier>' .
            '<xades:Description>' . $this->signerPolicy->name . '</xades:Description>' .
            '</xades:SigPolicyId>' .
            '<xades:SigPolicyHash>' .
            '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>' .
            '<ds:DigestValue>' . $this->signerPolicy->digest . '</ds:DigestValue>' .
            '</xades:SigPolicyHash>' .
            '</xades:SignaturePolicyId>' .
            '</xades:SignaturePolicyIdentifier>' .
            '<xades:SignerRole>' .
            '<xades:ClaimedRoles>' .
            '<xades:ClaimedRole>supplier</xades:ClaimedRole>' .
            '</xades:ClaimedRoles>' .
            '</xades:SignerRole>' .
            '</xades:SignedSignatureProperties>' .
            '</xades:SignedProperties>';
    }

    public function getSchemas(): string
    {

        $schema = match (strtolower($this->doctype)) {
            "fv" => 'xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" ',
            "nc" => 'xmlns="urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2" ',
            "nc" => 'xmlns="urn:oasis:names:specification:ubl:schema:xsd:DebitNote-2" ',
        };

        $schema .= 'xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2" xmlns:sts="http://www.dian.gov.co/contratos/facturaelectronica/v1/Structures" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" xmlns:xades141="http://uri.etsi.org/01903/v1.4.1#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"';

        return $schema;
    }

    public function getKeyInfo(): array|string
    {
        return '<ds:KeyInfo Id="' . $this->keyInfoId . '">' .
            '<ds:X509Data>' .
            '<ds:X509Certificate>' . $this->getPublicCertificate() . '</ds:X509Certificate>' .
            '</ds:X509Data>' .
            '</ds:KeyInfo>';
    }

    public function getPublicCertificate()
    {
        openssl_x509_export($this->certificate->publicKey, $tmpPEM);
        $tmpPEM = str_replace("-----BEGIN CERTIFICATE-----", "", $tmpPEM);
        $tmpPEM = str_replace("-----END CERTIFICATE-----", "", $tmpPEM);
        $tmpPEM = str_replace("\r", "", str_replace("\n", "", $tmpPEM));
        return $tmpPEM;
    }

    public function getSignedInfo($documentDigest, $kInfoDigest, $SignedPropertiesDigest)
    {
        return '<ds:SignedInfo>' .
            '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></ds:CanonicalizationMethod>' .
            '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod>' .
            '<ds:Reference Id="' . $this->reference0Id . '" URI="">' .
            '<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform></ds:Transforms>' .
            '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>' .
            '<ds:DigestValue>' . $documentDigest . '</ds:DigestValue>' .
            '</ds:Reference>' .
            '<ds:Reference URI="#' . $this->keyInfoId . '">' .
            '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>' .
            '<ds:DigestValue>' . $kInfoDigest . '</ds:DigestValue>' .
            '</ds:Reference>' .
            '<ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#' . $this->signedPropertiesId . '">' .
            '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>' .
            '<ds:DigestValue>' . $SignedPropertiesDigest . '</ds:DigestValue>' .
            '</ds:Reference>' .
            '</ds:SignedInfo>';
    }
}
