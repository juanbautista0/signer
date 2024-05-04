<?php


final class ResultType
{

    public function __construct(public  Error | null $error = null, public  mixed  $data = null)
    {
    }
}
