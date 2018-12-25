<?php

namespace Jwt;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Parser;

class Jwt
{
    const SECRET_KEY = "my_key";

    public static function encode(array $data): string
    {
        if (!empty($data)) {
            $builder = new Builder();

            $signer = new Sha256();

            $builder->setExpiration(time() + 3600);

            $builder->set('data', $data);

            $builder->sign($signer, self::SECRET_KEY);

            $token = $builder->getToken();

            return (string)$token;
        }
        return "";
    }

    public static function decode(string $token): array
    {
        try {
            $parse = (new Parser())->parse($token);

            if (!$parse->verify(new Sha256(), self::SECRET_KEY)) {
                throw new \Exception();
                return [];
            }

            return json_decode(json_encode($parse->getClaim('data')), true);

        } catch (\Exception $e) {
            var_dump($e->getTraceAsString());//use log instead
            return [];
        }
    }
}