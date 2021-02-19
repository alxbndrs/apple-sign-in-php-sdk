<?php

declare(strict_types=1);

namespace Azimo\Apple\Auth\Service;

use Azimo\Apple\Api\AppleApiClient;
use Azimo\Apple\Api\Factory\ResponseFactory;
use Azimo\Apple\Auth\Exception;
use Azimo\Apple\Auth\Factory\AppleJwtStructFactory;
use Azimo\Apple\Auth\Jwt;
use Azimo\Apple\Auth\Struct\JwtPayload;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Validator;
use phpseclib\Crypt\RSA;

final class AppleJwtFetchingService implements AppleJwtFetchingServiceInterface
{
    private Jwt\JwtParser $parser;
    private Jwt\JwtVerifier $verifier;
    private Jwt\JwtValidator $validator;
    private AppleJwtStructFactory $factory;

    public function __construct(
        string $appleUri,
        string $issuer,
        string $audience
    ) {
        $this->parser = $this->initParser();
        $this->verifier = $this->initVerifier($appleUri);
        $this->validator = $this->initValidator($issuer, $audience);
        $this->factory = new AppleJwtStructFactory();
    }

    /**
     * @throws Exception\InvalidCryptographicAlgorithmException
     * @throws Exception\InvalidJwtException
     * @throws Exception\KeysFetchingFailedException
     * @throws Exception\MissingClaimException
     * @throws Exception\ValidationFailedException
     * @throws Exception\VerificationFailedException
     */
    public function getJwtPayload(string $jwt): JwtPayload
    {
        $parsedJwt = $this->parser->parse($jwt);

        if (!$this->verifier->verify($parsedJwt)) {
            throw new Exception\VerificationFailedException(
                sprintf(
                    'Verification of given `%s` token failed. '
                    . 'Possibly incorrect public key used or token is malformed.',
                    $jwt
                )
            );
        }
        if (!$this->validator->isValid($parsedJwt)) {
            throw new Exception\ValidationFailedException('Validation of given token failed. Possibly token expired.');
        }

        return $this->factory->createJwtPayloadFromToken($parsedJwt);
    }

    private function initParser(): Jwt\JwtParser
    {
        return new Jwt\JwtParser(new Parser(new JoseEncoder()));
    }

    private function initVerifier(string $appleUri): Jwt\JwtVerifier
    {
        return new Jwt\JwtVerifier(
            new AppleApiClient($this->initHttpClient($appleUri), new ResponseFactory()),
            new Validator(),
            new RSA(),
            new Sha256()
        );
    }

    private function initValidator(string $issuer, string $audience): Jwt\JwtValidator
    {
        return new Jwt\JwtValidator(
            new Validator(),
            [
                new IssuedBy($issuer),
                new PermittedFor($audience),
            ]
        );
    }

    private function initHttpClient(string $appleUri): ClientInterface
    {
        return new Client([
            'base_uri' => $appleUri,
            'timeout'         => 5,
            'connect_timeout' => 5,
        ]);
    }
}
