# Firmador de Documentos XML de Facturación Electrónica DIAN

```php
use Juanbautista0/Signer/Policy;
use Juanbautista0/Signer/Tools/CertificateHandler;
use Juanbautista0/Signer/Tools/SignerPolicy;


$unsignedXml    =  '<Invoice xmlns="urn:oasis:names: ...';
$docType        ="fv";
$uuid           ="{{UUIDV4}}";

$certificate            = new CertificateHandler();
$certicate->publicKey   = "{{CERTICATE_PUBLIC_KEY}}";
$certicate->privateKey  = "{{CERTICATE_PRIVATE_KEY}}";
$certicate->path        = "{{CERTICATE_PATH}}";
$certicate->password    = "{{CERTICATE_PASSWORD}}";

$signerPolicy   =   new SignerPolicy();
$signatureTool  =    new Policy($signerPolicy, $certificate, $unsignedXml, $docType);
$signatureTool->Sign();

```
