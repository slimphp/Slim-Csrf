<?php

declare(strict_types=1);

namespace Slim\HttpCache\Tests;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Csrf\Guard;
use Slim\MiddlewareDispatcher;
use Slim\Psr7\Environment;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\UriFactory;
use Slim\Psr7\Headers;
use Slim\Psr7\Request;
use Slim\Psr7\Response;
use Slim\Psr7\Stream;

class CsrfTest extends TestCase
{
    /**
     * PSR7 request object
     *
     * @var \Psr\Http\Message\RequestInterface
     */
    protected $request;

    /**
     * PSR7 response object
     *
     * @var \Psr\Http\Message\ResponseInterface
     */
    protected $response;

    /**
     * @var ResponseFactory
     */
    protected $responseFactory;

    /**
     * @var MiddlewareDispatcher
     */
    protected $middlewareDispatcher;

    /**
     * Run before each test
     */
    public function setUp()
    {
        $uri = (new UriFactory())->createUri('https://example.com:443/foo/bar?abc=123');
        $headers = new Headers();
        $cookies = [];
        $serverParams = Environment::mock();
        $body = new Stream(fopen('php://temp', 'r+'));
        $this->request = new Request('GET', $uri, $headers, $cookies, $serverParams, $body);

        $this->response = new Response();

        $this->responseFactory = new ResponseFactory();

        $this->middlewareDispatcher = new MiddlewareDispatcher($this->createMock(RequestHandlerInterface::class));
    }

    public function testTokenKeys()
    {
        $mw = new Guard('test');

        $this->assertEquals('test_name', $mw->getTokenNameKey());
        $this->assertEquals('test_value', $mw->getTokenValueKey());
    }

    public function testTokenGeneration()
    {
        $storage = [];
        $request = $this->request;
        $responseFactory = $this->responseFactory;
        $mw = new Guard('csrf', $storage);
        $mw2 = function (
            ServerRequestInterface $request,
            RequestHandlerInterface $handler
        ) use (
            $mw,
            $responseFactory
        ): ResponseInterface {
            return $responseFactory->createResponse()
                ->withHeader('X-CSRF-NAME', $request->getAttribute($mw->getTokenNameKey()))
                ->withHeader('X-CSRF-VALUE', $request->getAttribute($mw->getTokenValueKey()));
        };

        $this->middlewareDispatcher->addCallable($mw2);
        $this->middlewareDispatcher->addMiddleware($mw);
        $response1 = $this->middlewareDispatcher->handle($request);
        $response2 = $this->middlewareDispatcher->handle($request);

        $this->assertStringStartsWith(
            'csrf',
            $response1->getHeaderLine('X-CSRF-NAME'),
            'Name key should start with csrf prefix'
        );
        $this->assertStringStartsWith(
            'csrf',
            $response2->getHeaderLine('X-CSRF-NAME'),
            'Name key should start with csrf prefix'
        );

        $this->assertNotEquals(
            $response1->getHeaderLine('X-CSRF-NAME'),
            $response2->getHeaderLine('X-CSRF-NAME'),
            'Generated token names must be unique'
        );

        $this->assertEquals(
            32,
            strlen($response1->getHeaderLine('X-CSRF-VALUE')),
            'Length of the generated token value should be double the strength'
        );
        $this->assertEquals(
            32,
            strlen($response2->getHeaderLine('X-CSRF-VALUE')),
            'Length of the generated token value should be double the strength'
        );

        $this->assertTrue(
            ctype_xdigit($response1->getHeaderLine('X-CSRF-VALUE')),
            'Generated token value is not hexadecimal'
        );
        $this->assertTrue(
            ctype_xdigit($response2->getHeaderLine('X-CSRF-VALUE')),
            'Generated token value is not hexadecimal'
        );
    }

    public function testValidToken()
    {
        $storage = ['csrf_123' => 'xyz'];
        $request = $this->request
                        ->withMethod('POST')
                        ->withParsedBody([
                            'csrf_name' => 'csrf_123',
                            'csrf_value' => 'xyz'
                        ]);
        $mw = new Guard('csrf', $storage);
        $responseFactory = $this->responseFactory;
        $mw2 = function (
            ServerRequestInterface $request,
            RequestHandlerInterface $handler
        ) use (
            $mw,
            $responseFactory
        ): ResponseInterface {
            return $responseFactory->createResponse();
        };

        $this->middlewareDispatcher->addMiddleware($mw);
        $this->middlewareDispatcher->addCallable($mw2);
        $newResponse = $this->middlewareDispatcher->handle($request);

        $this->assertEquals(200, $newResponse->getStatusCode());
    }

    public function testInvalidToken()
    {
        $storage = ['csrf_123' => 'abc']; // <-- Invalid token value
        $request = $this->request
                        ->withMethod('POST')
                        ->withParsedBody([
                            'csrf_name' => 'csrf_123',
                            'csrf_value' => 'xyz'
                        ]);
        $mw = new Guard('csrf', $storage);
        $this->middlewareDispatcher->addMiddleware($mw);
        $newResponse = $this->middlewareDispatcher->handle($request);

        $this->assertEquals(400, $newResponse->getStatusCode());
    }

    public function testMissingToken()
    {
        $storage = []; // <-- Missing token name and value
        $request = $this->request
                        ->withMethod('POST')
                        ->withParsedBody([
                            'csrf_name' => 'csrf_123',
                            'csrf_value' => 'xyz'
                        ]);
        $mw = new Guard('csrf', $storage);
        $this->middlewareDispatcher->addMiddleware($mw);
        $newResponse = $this->middlewareDispatcher->handle($request);

        $this->assertEquals(400, $newResponse->getStatusCode());
    }

    public function testExternalStorageOfAnArrayAccessPersists()
    {
        $storage = new \ArrayObject();

        $request = $this->request
                        ->withMethod('POST')
                        ->withParsedBody([
                            'csrf_name' => 'csrf_123',
                            'csrf_value' => 'xyz'
                        ]);
        $mw = new Guard('csrf', $storage);

        $this->assertEquals(0, count($storage));
        $this->middlewareDispatcher->addMiddleware($mw);
        $newResponse = $this->middlewareDispatcher->handle($request);
        $this->assertEquals(1, count($storage));
    }

    public function testExternalStorageOfAnArrayPersists()
    {
        $storage = [];

        $request = $this->request
                        ->withMethod('POST')
                        ->withParsedBody([
                            'csrf_name' => 'csrf_123',
                            'csrf_value' => 'xyz'
                        ]);
        $mw = new Guard('csrf', $storage);

        $this->assertEquals(0, count($storage));
        $this->middlewareDispatcher->addMiddleware($mw);
        $newResponse = $this->middlewareDispatcher->handle($request);
        $this->assertEquals(1, count($storage));
    }

    public function testPersistenceModeTrueBetweenRequestsArray()
    {
        $storage = [];

        $mw = new Guard('csrf', $storage, null, 200, 16, true);

        $responseFactory = $this->responseFactory;
        $mw2 = function (
            ServerRequestInterface $request,
            RequestHandlerInterface $handler
        ) use (
            $mw,
            $responseFactory
        ): ResponseInterface {
            // Token name and value should be accessible in the middleware as request attributes
            $this->assertEquals($mw->getTokenName(), $request->getAttribute('csrf_name'));
            $this->assertEquals($mw->getTokenValue(), $request->getAttribute('csrf_value'));
            return $responseFactory->createResponse();
        };

        // Token name and value should be null if the storage is empty and middleware has not yet been invoked
        $this->assertNull($mw->getTokenName());
        $this->assertNull($mw->getTokenValue());

        $this->middlewareDispatcher->addMiddleware($mw);
        $response = $this->middlewareDispatcher->handle($this->request);

        // Persistent token name and value have now been generated
        $name = $mw->getTokenName();
        $value = $mw->getTokenValue();

        // Subsequent request will attempt to validate the token
        $request = $this->request
                        ->withMethod('POST')
                        ->withParsedBody([
                            'csrf_name' => $name,
                            'csrf_value' => $value
                        ]);
        $this->middlewareDispatcher->addMiddleware($mw);
        $response = $this->middlewareDispatcher->handle($request);

        // Token name and value should be the same after subsequent request
        $this->assertEquals($name, $mw->getTokenName());
        $this->assertEquals($value, $mw->getTokenValue());
    }

    public function testPersistenceModeTrueBetweenRequestsArrayAccess()
    {
        $storage = new \ArrayObject();

        $mw = new Guard('csrf', $storage, null, 200, 16, true);

        $responseFactory = $this->responseFactory;
        $mw2 = function (
            ServerRequestInterface $request,
            RequestHandlerInterface $handler
        ) use (
            $mw,
            $responseFactory
        ): ResponseInterface {
            // Token name and value should be accessible in the middleware as request attributes
            $this->assertEquals($mw->getTokenName(), $request->getAttribute('csrf_name'));
            $this->assertEquals($mw->getTokenValue(), $request->getAttribute('csrf_value'));
            return $responseFactory->createResponse();
        };

        // Token name and value should be null if the storage is empty and middleware has not yet been invoked
        $this->assertNull($mw->getTokenName());
        $this->assertNull($mw->getTokenValue());

        $this->middlewareDispatcher->addMiddleware($mw);
        $response = $this->middlewareDispatcher->handle($this->request);

        // Persistent token name and value have now been generated
        $name = $mw->getTokenName();
        $value = $mw->getTokenValue();

        // Subsequent request will attempt to validate the token
        $request = $this->request
                        ->withMethod('POST')
                        ->withParsedBody([
                            'csrf_name' => $name,
                            'csrf_value' => $value
                        ]);
        $this->middlewareDispatcher->addMiddleware($mw);
        $response = $this->middlewareDispatcher->handle($request);

        // Token name and value should be the same after subsequent request
        $this->assertEquals($name, $mw->getTokenName());
        $this->assertEquals($value, $mw->getTokenValue());
    }

    public function testPersistenceModeFalseBetweenRequestsArray()
    {
        $storage = [];

        $mw = new Guard('csrf', $storage);

        $responseFactory = $this->responseFactory;
        $mw2 = function (
            ServerRequestInterface $request,
            RequestHandlerInterface $handler
        ) use (
            $mw,
            $responseFactory
        ): ResponseInterface {
            // Token name and value should be accessible in the middleware as request attributes
            $this->assertEquals($mw->getTokenName(), $request->getAttribute('csrf_name'));
            $this->assertEquals($mw->getTokenValue(), $request->getAttribute('csrf_value'));
            return $responseFactory->createResponse();
        };

        // Token name and value should be null if the storage is empty and middleware has not yet been invoked
        $this->assertNull($mw->getTokenName());
        $this->assertNull($mw->getTokenValue());

        $this->middlewareDispatcher->addMiddleware($mw);
        $response = $this->middlewareDispatcher->handle($this->request);

        // First token name and value have now been generated
        $name = $mw->getTokenName();
        $value = $mw->getTokenValue();

        // Subsequent request will attempt to validate the token
        $request = $this->request
                        ->withMethod('POST')
                        ->withParsedBody([
                            'csrf_name' => $name,
                            'csrf_value' => $value
                        ]);
        $this->middlewareDispatcher->addMiddleware($mw);
        $response = $this->middlewareDispatcher->handle($request);

        // Token name and value should NOT be the same after subsequent request
        $this->assertNotEquals($name, $mw->getTokenName());
        $this->assertNotEquals($value, $mw->getTokenValue());
    }

    public function testPersistenceModeFalseBetweenRequestsArrayAccess()
    {
        $storage = new \ArrayObject();

        $mw = new Guard('csrf', $storage);

        $responseFactory = $this->responseFactory;
        $mw2 = function (
            ServerRequestInterface $request,
            RequestHandlerInterface $handler
        ) use (
            $mw,
            $responseFactory
        ): ResponseInterface {
            // Token name and value should be accessible in the middleware as request attributes
            $this->assertEquals($mw->getTokenName(), $request->getAttribute('csrf_name'));
            $this->assertEquals($mw->getTokenValue(), $request->getAttribute('csrf_value'));
            return $responseFactory->createResponse();
        };

        // Token name and value should be null if the storage is empty and middleware has not yet been invoked
        $this->assertNull($mw->getTokenName());
        $this->assertNull($mw->getTokenValue());

        $this->middlewareDispatcher->addMiddleware($mw);
        $response = $this->middlewareDispatcher->handle($this->request);

        // First token name and value have now been generated
        $name = $mw->getTokenName();
        $value = $mw->getTokenValue();

        // Subsequent request will attempt to validate the token
        $request = $this->request
                        ->withMethod('POST')
                        ->withParsedBody([
                            'csrf_name' => $name,
                            'csrf_value' => $value
                        ]);
        $this->middlewareDispatcher->addMiddleware($mw);
        $response = $this->middlewareDispatcher->handle($request);

        // Token name and value should NOT be the same after subsequent request
        $this->assertNotEquals($name, $mw->getTokenName());
        $this->assertNotEquals($value, $mw->getTokenValue());
    }

    public function testUpdateAfterInvalidTokenWithPersistenceModeTrue()
    {
        $storage = [];

        $mw = new Guard('csrf', $storage, null, 200, 16, true);

        $this->middlewareDispatcher->addMiddleware($mw);
        $response = $this->middlewareDispatcher->handle($this->request);

        // Persistent token name and value have now been generated
        $name = $mw->getTokenName();
        $value = $mw->getTokenValue();

        // Bad request, token should get updated
        $request = $this->request
                        ->withMethod('POST')
                        ->withParsedBody([
                            'csrf_name' => 'csrf_123',
                            'csrf_value' => 'xyz'
                        ]);
        $this->middlewareDispatcher->addMiddleware($mw);
        $response = $this->middlewareDispatcher->handle($request);

        // Token name and value should NOT be the same after subsequent request
        $this->assertNotEquals($name, $mw->getTokenName());
        $this->assertNotEquals($value, $mw->getTokenValue());
    }

    public function testStorageLimitIsEnforcedForObjects()
    {
        $storage = new \ArrayObject();

        $request = $this->request;

        $mw = new Guard('csrf', $storage);
        $mw->setStorageLimit(2);

        $this->assertEquals(0, count($storage));

        $this->middlewareDispatcher->addMiddleware($mw);
        $response = $this->middlewareDispatcher->handle($request);
        $response = $this->middlewareDispatcher->handle($request);
        $response = $this->middlewareDispatcher->handle($request);
        $this->assertEquals(2, count($storage));
    }

    public function testStorageLimitIsEnforcedForArrays()
    {
        $storage = [];

        $request = $this->request;

        $mw = new Guard('csrf', $storage);
        $mw->setStorageLimit(2);

        $this->assertEquals(0, count($storage));

        $this->middlewareDispatcher->addMiddleware($mw);
        $response = $this->middlewareDispatcher->handle($request);
        $response = $this->middlewareDispatcher->handle($request);
        $response = $this->middlewareDispatcher->handle($request);
        $this->assertEquals(2, count($storage));
    }

    public function testKeyPair()
    {
        $mw = new Guard();

        $this->middlewareDispatcher->addMiddleware($mw);
        $response = $this->middlewareDispatcher->handle($this->request);

        $this->assertNotNull($mw->getTokenName());

        $this->assertNotNull($mw->getTokenValue());
    }

    public function testDefaultStorageIsSession()
    {
        $sessionBackup = $_SESSION;
        $_SESSION = array();

        $mw = new Guard('csrf');
        $mw->validateStorage();

        $this->assertNotEmpty($_SESSION);

        $_SESSION = $sessionBackup;
    }
}
