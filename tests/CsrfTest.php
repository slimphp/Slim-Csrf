<?php
namespace Slim\HttpCache\Tests;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Slim\Http\Body;
use Slim\Http\Collection;
use Slim\Http\Environment;
use Slim\Http\Headers;
use Slim\Http\Request;
use Slim\Http\Response;
use Slim\Http\Uri;
use Slim\Csrf\Guard;

class CsrfTest extends \PHPUnit_Framework_TestCase
{
    /**
     * PSR7 request object
     *
     * @var Psr\Http\Message\RequestInterface
     */
    protected $request;

    /**
     * PSR7 response object
     *
     * @var Psr\Http\Message\ResponseInterface
     */
    protected $response;

    /**
     * Run before each test
     */
    public function setUp()
    {
        $uri = Uri::createFromString('https://example.com:443/foo/bar?abc=123');
        $headers = new Headers();
        $cookies = [];
        $env = Environment::mock();
        $serverParams = $env->all();
        $body = new Body(fopen('php://temp', 'r+'));
        $this->request = new Request('GET', $uri, $headers, $cookies, $serverParams, $body);
        $this->response = new Response;
    }

    public function testTokenKeys()
    {
        $mw = new Guard('test');

        $this->assertEquals('test_name', $mw->getTokenNameKey());
        $this->assertEquals('test_value', $mw->getTokenValueKey());
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
        $response = $this->response;
        $next = function ($req, $res) {
            return $res;
        };
        $mw = new Guard('csrf', $storage);
        $newResponse = $mw($request, $response, $next);

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
        $response = $this->response;
        $next = function ($req, $res) {
            return $res;
        };
        $mw = new Guard('csrf', $storage);
        $newResponse = $mw($request, $response, $next);

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
        $response = $this->response;
        $next = function ($req, $res) {
            return $res;
        };
        $mw = new Guard('csrf', $storage);
        $newResponse = $mw($request, $response, $next);

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
        $response = $this->response;
        $next = function ($req, $res) {
            return $res;
        };
        $mw = new Guard('csrf', $storage);

        $this->assertEquals(0, count($storage));
        $newResponse = $mw($request, $response, $next);
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
        $response = $this->response;
        $next = function ($req, $res) {
            return $res;
        };
        $mw = new Guard('csrf', $storage);

        $this->assertEquals(0, count($storage));
        $newResponse = $mw($request, $response, $next);
        $this->assertEquals(1, count($storage));
    }

    public function testStorageLimitIsEnforcedForObjects()
    {
        $storage = new \ArrayObject();
        
        $request = $this->request;
        $response = $this->response;
        $next = function ($req, $res) {
            return $res;
        };
        $mw = new Guard('csrf', $storage);
        $mw->setStorageLimit(2);

        $this->assertEquals(0, count($storage));
        $response = $mw($request, $response, $next);
        $response = $mw($request, $response, $next);
        $response = $mw($request, $response, $next);
        $this->assertEquals(2, count($storage));
    }

    public function testStorageLimitIsEnforcedForArrays()
    {
        $storage = [];
        
        $request = $this->request;
        $response = $this->response;
        $next = function ($req, $res) {
            return $res;
        };
        $mw = new Guard('csrf', $storage);
        $mw->setStorageLimit(2);

        $this->assertEquals(0, count($storage));
        $response = $mw($request, $response, $next);
        $response = $mw($request, $response, $next);
        $response = $mw($request, $response, $next);
        $this->assertEquals(2, count($storage));
    }

    public function testKeyPair() {
        $mw = new Guard();

        $next = function ($req, $res) {
            return $res;
        };

        $response = $mw($this->request, $this->response, $next);

        $this->assertNotNull($mw->getTokenName());

        $this->assertNotNull($mw->getTokenValue());
    }
}
