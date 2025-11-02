<?php

/**
 * Slim Framework (https://slimframework.com)
 *
 * @license https://github.com/slimphp/Slim-Csrf/blob/master/LICENSE.md (MIT License)
 */

declare(strict_types=1);

namespace Slim\Csrf\Tests;

use ArrayIterator;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Server\RequestHandlerInterface;
use ReflectionException;
use ReflectionMethod;
use RuntimeException;
use Slim\Csrf\Guard;

use function session_start;
use function substr;

class GuardTest extends TestCase
{
    protected function setAccessible(ReflectionMethod $property, bool $accessible = true): void
    {
        // only if PHP version < 8.1
        if (PHP_VERSION_ID >= 80100) {
            return;
        }
        $property->setAccessible($accessible);
    }


    /**
     * Helper function to mask a token using private method {@link Guard::maskToken()}
     *
     * @param Guard $middleware instance of the csrf middleware
     * @param string $token token to mask
     *
     * @return string masked token
     *
     * @throws ReflectionException
     */
    private function maskToken(Guard $middleware, string $token): string
    {
        $maskTokenMethod = new ReflectionMethod($middleware, 'maskToken');
        $this->setAccessible($maskTokenMethod);

        return $maskTokenMethod->invoke($middleware, $token);
    }

    public function testStrengthLowerThan16ThrowsException()
    {
        $storage = [];
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('CSRF middleware instantiation failed. Minimum strength is 16.');
        new Guard($responseFactory, 'test', $storage, null, 200, 15);
    }

    /**
     * Use session_start() before instantiating the Guard middleware or provide array storage.
     */
    public function testSetStorageThrowsExceptionWhenFallingBackOnSessionThatHasNotBeenStarted()
    {
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid CSRF storage.');
        new Guard($responseFactory, 'test');
    }

    /**
     * @runInSeparateProcess
     */
    public function testSetStorageSetsKeysOnSessionObjectWhenNotExist()
    {
        session_start();
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        new Guard($responseFactory, 'test');

        $this->assertArrayHasKey('test', $_SESSION);
    }

    public function testSetFailureHandler()
    {
        $storage = [];
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactory, 'test', $storage);

        $called = 0;
        $handler = function () use (&$called) {
            $called++;
            return $this->createMock(ResponseInterface::class);
        };
        $mw->setFailureHandler($handler);

        $request = $this->createMock(ServerRequestInterface::class);
        $request
            ->expects($this->once())
            ->method('getMethod')
            ->willReturn('POST');

        $request
            ->expects($this->exactly(2))
            ->method('withAttribute')
            ->with($this->isType('string'), $this->isType('string'))
            ->willReturn($request);

        $request
            ->expects($this->once())
            ->method('getParsedBody')
            ->willReturn([]);

        $request
            ->expects($this->exactly(2))
            ->method('getHeader')
            ->with($this->isType('string'))
            ->willReturn([]);

        $requestHandler = $this->createMock(RequestHandlerInterface::class);

        $mw->process($request, $requestHandler);
        $this->assertEquals(1, $called);
    }

    public function testDefaultFailureHandler()
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream
            ->expects($this->once())
            ->method('write')
            ->with('Failed CSRF check!');

        $response = $this->createMock(ResponseInterface::class);

        $response
            ->expects($this->once())
            ->method('getBody')
            ->willReturn($stream);

        $response
            ->expects($this->once())
            ->method('withStatus')
            ->with(400)
            ->willReturn($response);

        $response
            ->expects($this->once())
            ->method('withHeader')
            ->with('Content-Type', 'text/plain')
            ->willReturn($response);

        $response
            ->expects($this->once())
            ->method('withBody')
            ->with($stream)
            ->willReturn($response);

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory
            ->expects($this->once())
            ->method('createResponse')
            ->willReturn($response);

        $storage = [];
        $mw = new Guard($responseFactory, 'test', $storage);

        $request = $this->createMock(ServerRequestInterface::class);
        $request
            ->expects($this->once())
            ->method('getMethod')
            ->willReturn('POST');

        $request
            ->expects($this->exactly(2))
            ->method('withAttribute')
            ->with($this->isType('string'), $this->isType('string'))
            ->willReturn($request);

        $request
            ->expects($this->once())
            ->method('getParsedBody')
            ->willReturn([]);

        $request
            ->expects($this->exactly(2))
            ->method('getHeader')
            ->with($this->isType('string'))
            ->willReturn([]);

        $requestHandler = $this->createMock(RequestHandlerInterface::class);

        $actualResponse = $mw->process($request, $requestHandler);
        $this->assertSame($actualResponse, $response);
    }

    public function testValidateToken()
    {
        $storage = [
            'test-name' => 'value'
        ];
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactory, 'test', $storage);

        $maskedToken = $this->maskToken($mw, 'value');
        $this->assertTrue($mw->validateToken('test-name', $maskedToken));

        $maskedToken2 = $this->maskToken($mw, 'value');
        $this->assertTrue($mw->validateToken('test-name', $maskedToken2));

        $this->assertNotSame($maskedToken, $maskedToken2);
    }

    public function testNotValidatingBadToken()
    {
        $storage = [
            'test-name' => 'value'
        ];
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactory, 'test', $storage);

        $maskedToken = 'MY_BAD_BASE64???';
        $this->assertFalse($mw->validateToken('test-name', $maskedToken), 'Token contains bad base64 characters');

        $maskedToken2 = $this->maskToken($mw, 'value');
        // Remove some part of base64
        $maskedToken2 = substr($maskedToken2, 0, -6);
        $this->assertFalse($mw->validateToken('test-name', $maskedToken2), 'Token size should be even');
    }

    public function testGetTokenNameAndValue()
    {
        $storage = [];
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactory, 'test', $storage);

        $this->assertNull($mw->getTokenName());
        $this->assertNull($mw->getTokenValue());

        $loadLastKeyPairMethod = new ReflectionMethod($mw, 'loadLastKeyPair');
        $this->setAccessible($loadLastKeyPairMethod);
        $loadLastKeyPairMethod->invoke($mw);

        $storage = [
            'test-name' => 'value',
        ];
        $mw->setStorage($storage);
        $loadLastKeyPairMethod->invoke($mw);

        $this->assertEquals('test-name', $mw->getTokenName());

        $unmaskTokenMethod = new ReflectionMethod($mw, 'unmaskToken');
        $this->setAccessible($unmaskTokenMethod);
        $unmaskedToken = $unmaskTokenMethod->invoke($mw, $mw->getTokenValue());
        $this->assertEquals('value', $unmaskedToken);
    }

    public function testGetPersistentTokenMode()
    {
        $storage = [];
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactory, 'test', $storage, null, 200, 16, true);

        $this->assertTrue($mw->getPersistentTokenMode());
    }

    public function testGetTokenNameKeyAndValue()
    {
        $storage = [];
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactory, 'test', $storage);

        $this->assertEquals('test-name', $mw->getTokenNameKey());
        $this->assertEquals('test-value', $mw->getTokenValueKey());
    }

    public function testRemoveTokenFromStorage()
    {
        $storage = [
            'test-name' => 'value',
        ];
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactory, 'test', $storage);

        $removeTokenFromStorageMethod = new ReflectionMethod($mw, 'removeTokenFromStorage');
        $this->setAccessible($removeTokenFromStorageMethod);
        $removeTokenFromStorageMethod->invoke($mw, 'test-name');

        $this->assertArrayNotHasKey('test-name', $storage);
    }

    public function testEnforceStorageLimitWithArray()
    {
        $storage = [
            'test-name' => 'value',
            'test-name2' => 'value2',
        ];
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactory, 'test', $storage, null, 1);

        $enforceStorageLimitMethod = new ReflectionMethod($mw, 'enforceStorageLimit');
        $this->setAccessible($enforceStorageLimitMethod);
        $enforceStorageLimitMethod->invoke($mw);

        $this->assertArrayNotHasKey('test-name', $storage);
        $this->assertArrayHasKey('test-name2', $storage);
    }

    public function testNotEnforceStorageLimitWithArrayWhenLimitIsZero()
    {
        $initial_storage = $storage = [
            'test-name' => 'value',
            'test-name2' => 'value2',
        ];
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactory, 'test', $storage, null, 0);

        $enforceStorageLimitMethod = new ReflectionMethod($mw, 'enforceStorageLimit');
        $this->setAccessible($enforceStorageLimitMethod);
        $enforceStorageLimitMethod->invoke($mw);

        $this->assertSame($initial_storage, $storage);
    }

    public function testEnforceStorageLimitWithIterator()
    {
        $storage = new ArrayIterator([
            'test-name' => 'value',
            'test-name2' => 'value',
        ]);
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactory, 'test', $storage, null, 1);

        $enforceStorageLimitMethod = new ReflectionMethod($mw, 'enforceStorageLimit');
        $this->setAccessible($enforceStorageLimitMethod);
        $enforceStorageLimitMethod->invoke($mw);

        $this->assertArrayNotHasKey('test-name', $storage);
        $this->assertArrayHasKey('test-name2', $storage);
    }

    public function testTokenIsRemovedFromStorageWhenPersistentModeIsOff()
    {
        $storage = [
            'test-name' => 'test-value123',
        ];

        $response = $this->createMock(ResponseInterface::class);

        $requestHandler = $this->createMock(RequestHandlerInterface::class);
        $requestHandler
            ->expects($this->once())
            ->method('handle')
            ->with($this->isInstanceOf(ServerRequestInterface::class))
            ->willReturn($response);

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);

        $mw = new Guard($responseFactory, 'test', $storage);

        $request = $this->createMock(ServerRequestInterface::class);
        $request
            ->expects($this->once())
            ->method('getMethod')
            ->willReturn('POST');
        $request
            ->expects($this->exactly(2))
            ->method('withAttribute')
            ->with($this->isType('string'), $this->isType('string'))
            ->willReturn($request);
        $request
            ->expects($this->once())
            ->method('getParsedBody')
            ->willReturn([
                'test-name' => 'test-name',
                'test-value' => $this->maskToken($mw, 'test-value123'),
            ]);

        $mw->process($request, $requestHandler);
        self::assertArrayNotHasKey('test-name', $storage);
    }

    public function testTokenIsRemovedFromStorageWhenPersistentModeIsOffOnFailure()
    {
        $storage = [
            'test-name' => 'test-value123',
            'test-name2' => 'test-value234',
        ];

        $stream = $this->createMock(StreamInterface::class);
        $stream
            ->expects($this->once())
            ->method('write')
            ->with('Failed CSRF check!');

        $response = $this->createMock(ResponseInterface::class);

        $response
            ->expects($this->once())
            ->method('getBody')
            ->willReturn($stream);

        $response
            ->expects($this->once())
            ->method('withStatus')
            ->with(400)
            ->willReturn($response);

        $response
            ->expects($this->once())
            ->method('withHeader')
            ->with('Content-Type', 'text/plain')
            ->willReturn($response);

        $response
            ->expects($this->once())
            ->method('withBody')
            ->with($stream)
            ->willReturn($response);

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory
            ->expects($this->once())
            ->method('createResponse')
            ->willReturn($response);

        $requestHandler = $this->createMock(RequestHandlerInterface::class);

        $mw = new Guard($responseFactory, 'test', $storage, null, 1);
        $mw->setStorage($storage); // pass $storage in by reference so we can inspect it later

        $request = $this->createMock(ServerRequestInterface::class);
        $request
            ->expects($this->once())
            ->method('getMethod')
            ->willReturn('GET');

        $request
            ->expects($this->once())
            ->method('getParsedBody')
            ->willReturn([
                             'test-name' => 'test-value123',
                         ]);

        $mw->process($request, $requestHandler);

        $this->assertArrayNotHasKey('test-name', $storage);
    }

    public function testTokenInBodyOfGetIsInvalid()
    {
        $storage = [
            'test-name' => 'test-value123',
        ];

        // we set up a failure handler that we expect to be called because a GET cannot have a token
        $failureHandlerCalled = 0;
        $failureHandler = function () use (&$failureHandlerCalled) {
            $failureHandlerCalled++;
            return $this->createMock(ResponseInterface::class);
        };

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);

        $mw = new Guard($responseFactory, 'test', $storage, $failureHandler);

        $requestHandler = $this->createMock(RequestHandlerInterface::class);

        $request = $this->createMock(ServerRequestInterface::class);
        $request
            ->expects($this->once())
            ->method('getMethod')
            ->willReturn('GET');
        $request
            ->expects($this->once())
            ->method('getParsedBody')
            ->willReturn([
                'test-name' => 'test-name',
                'test-value' => 'test-value123',
            ]);

        $mw->process($request, $requestHandler);
        self::assertSame(1, $failureHandlerCalled);
    }

    public function testProcessAppendsNewTokensWhenPersistentTokenModeIsOff()
    {
        $storage = [];
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactory, 'test', $storage);

        $response = $this->createMock(ResponseInterface::class);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getParsedBody')->willReturn(null);
        $request->expects($this->exactly(2))->method('getHeader')->with($this->isType('string'))->willReturn([]);
        $request
            ->expects($this->once())
            ->method('getMethod')
            ->willReturn('GET');

        $request
            ->expects($this->exactly(2))
            ->method('withAttribute')
            ->with($this->isType('string'), $this->isType('string'))
            ->willReturn($request);

        $requestHandler = $this->createMock(RequestHandlerInterface::class);

        $requestHandler
            ->expects($this->once())
            ->method('handle')
            ->with($request)
            ->willReturn($response);

        $mw->process($request, $requestHandler);
    }

    public function testProcessAppendsNewTokensWhenPersistentTokenModeIsOn()
    {
        $storage = [
            'test-name123' => 'test-value123',
        ];
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactory, 'test', $storage, null, 200, 16, true);

        $response = $this->createMock(ResponseInterface::class);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getParsedBody')->willReturn(null);
        $request->expects($this->exactly(2))->method('getHeader')->with($this->isType('string'))->willReturn([]);
        $request
            ->expects($this->once())
            ->method('getMethod')
            ->willReturn('GET');

        $request
            ->expects($this->exactly(2))
            ->method('withAttribute')
            ->withConsecutive(
                ['test-name', 'test-name123'],
                ['test-value', $this->isType('string')]
            )
            ->willReturn($request);

        $requestHandler = $this->createMock(RequestHandlerInterface::class);
        $requestHandler
            ->expects($this->once())
            ->method('handle')
            ->with($request)
            ->willReturn($response);

        $mw->process($request, $requestHandler);
    }

    public function testCanGetLastKeyPairFromIterator()
    {
        $storage = new ArrayIterator([
            'test-key1' => 'value1',
            'test-key2' => 'value2',
        ]);
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactory, 'test', $storage, null, 1);

        $enforceStorageLimitMethod = new ReflectionMethod($mw, 'getLastKeyPair');
        $this->setAccessible($enforceStorageLimitMethod);
        $keyPair = $enforceStorageLimitMethod->invoke($mw);

        $this->assertIsArray($keyPair);
        $this->assertArrayHasKey('test-name', $keyPair);
        $this->assertArrayHasKey('test-value', $keyPair);
        $this->assertEquals('test-key2', $keyPair['test-name']);

        $unmaskTokenMethod = new ReflectionMethod($mw, 'unmaskToken');
        $this->setAccessible($unmaskTokenMethod);
        $unmaskedToken = $unmaskTokenMethod->invoke($mw, $keyPair['test-value']);
        $this->assertEquals('value2', $unmaskedToken);
    }

    public function testTokenFromHeaderOnDelete()
    {
        $storage = [
            'test-name' => 'test-value123',
        ];

        $response = $this->createMock(ResponseInterface::class);

        $requestHandler = $this->createMock(RequestHandlerInterface::class);
        $requestHandler
            ->expects($this->once())
            ->method('handle')
            ->with($this->isInstanceOf(ServerRequestInterface::class))
            ->willReturn($response);

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);

        $mw = new Guard($responseFactory, 'test', $storage);

        $request = $this->createMock(ServerRequestInterface::class);
        $request
            ->expects($this->once())
            ->method('getMethod')
            ->willReturn('DELETE');
        $request
            ->expects($this->exactly(2))
            ->method('withAttribute')
            ->with($this->isType('string'), $this->isType('string'))
            ->willReturn($request);
        $request
            ->expects($this->once())
            ->method('getParsedBody')
            ->willReturn([]);
        $request
            ->expects($this->exactly(2))
            ->method('getHeader')
            ->withConsecutive(['test-name'], ['test-value'])
            ->willReturnOnConsecutiveCalls(['test-name'], [$this->maskToken($mw, 'test-value123')]);

        $mw->process($request, $requestHandler);
    }
}
