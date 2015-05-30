<?php
namespace Slim\HttpCache\Tests;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
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
        $uri = \Slim\Http\Uri::createFromString('https://example.com:443/foo/bar?abc=123');
        $headers = new \Slim\Http\Headers();
        $cookies = new \Slim\Http\Collection();
        $env = \Slim\Http\Environment::mock();
        $serverParams = new \Slim\Http\Collection($env->all());
        $body = new \Slim\Http\Body(fopen('php://temp', 'r+'));
        $this->request = new \Slim\Http\Request('GET', $uri, $headers, $cookies, $serverParams, $body);
        $this->response = new \Slim\Http\Response;
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
}
