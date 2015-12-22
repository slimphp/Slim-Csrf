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

    public function testTokenGeneration()
    {
        $storage = [];
        $request = $this->request;
        $response = $this->response;
        $mw = new Guard('csrf', $storage);
        $next = function ($req, $res) use ($mw) {
            return $res
                ->withHeader('X-CSRF-NAME',  $req->getAttribute($mw->getTokenNameKey()))
                ->withHeader('X-CSRF-VALUE', $req->getAttribute($mw->getTokenValueKey()));
        };
        $response1 = $mw($request, $response, $next);
        $response2 = $mw($request, $response, $next);
        
        $this->assertStringStartsWith('csrf', $response1->getHeaderLine('X-CSRF-NAME'), 'Name key should start with csrf prefix');
        $this->assertStringStartsWith('csrf', $response2->getHeaderLine('X-CSRF-NAME'), 'Name key should start with csrf prefix');
        
        $this->assertNotEquals($response1->getHeaderLine('X-CSRF-NAME'), $response2->getHeaderLine('X-CSRF-NAME'), 'Generated token names must be unique');
        
        $this->assertEquals(32, strlen($response1->getHeaderLine('X-CSRF-VALUE')), 'Length of the generated token value should be double the strength');
        $this->assertEquals(32, strlen($response2->getHeaderLine('X-CSRF-VALUE')), 'Length of the generated token value should be double the strength');
        
        $this->assertTrue(ctype_xdigit($response1->getHeaderLine('X-CSRF-VALUE')), 'Generated token value is not hexadecimal');
        $this->assertTrue(ctype_xdigit($response2->getHeaderLine('X-CSRF-VALUE')), 'Generated token value is not hexadecimal');
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
