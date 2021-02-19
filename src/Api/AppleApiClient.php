<?php

declare(strict_types=1);

namespace Azimo\Apple\Api;

use Azimo\Apple\Api\Exception\PublicKeyFetchingFailedException;
use Azimo\Apple\Api\Factory\ResponseFactory;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Utils;

final class AppleApiClient implements AppleApiClientInterface
{
    private ClientInterface $httpClient;
    private ResponseFactory $responseFactory;

    public function __construct(ClientInterface $httpClient, ResponseFactory $responseFactory)
    {
        $this->httpClient = $httpClient;
        $this->responseFactory = $responseFactory;
    }

    public function getAuthKeys(): Response\JsonWebKeySetCollection
    {
        try {
            $response = $this->httpClient->send(new Request('GET', 'auth/keys'));
        } catch (GuzzleException $exception) {
            throw new PublicKeyFetchingFailedException($exception->getMessage(), $exception->getCode(), $exception);
        }

        try {
            return $this->responseFactory->createFromArray(
                Utils::jsonDecode($response->getBody()->getContents(), true)
            );
        } catch (\InvalidArgumentException $exception) {
            throw new Exception\InvalidResponseException(
                'Unable to decode response',
                $exception->getCode(),
                $exception
            );
        }
    }
}
