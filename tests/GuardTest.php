<?php
/**
 * Slim Framework (https://slimframework.com)
 *
 * @license https://github.com/slimphp/Slim-Csrf/blob/master/LICENSE.md (MIT License)
 */

declare(strict_types=1);

namespace Slim\Tests\Csrf;

use ArrayIterator;
use Exception;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Server\RequestHandlerInterface;
use ReflectionMethod;
use RuntimeException;
use Slim\Csrf\Guard;

class GuardTest extends TestCase
{
    /**
     * @expectedException Exception
     * @expectedExceptionMessage CSRF middleware instantiation failed. Minimum strength is 16.
     */
    public function testStrengthLowerThan16ThrowsException()
    {
        $storage = [];
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage, null, 200, 15);
    }

    /**
     * @expectedException RuntimeException
     * @expectedExceptionMessage Invalid CSRF storage.
     * Use session_start() before instantiating the Guard middleware or provide array storage.
     */
    public function testSetStorageThrowsExceptionWhenFallingBackOnSessionThatHasNotBeenStarted()
    {
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test');
    }

    /**
     * @runInSeparateProcess
     */
    public function testSetStorageSetsKeysOnSessionObjectWhenNotExist()
    {
        session_start();
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test');

        $this->assertArrayHasKey('test', $_SESSION);
    }

    public function testSetFailureHandler()
    {
        $self = $this;

        $storage = [];
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage);

        $called = 0;
        $handler = function () use ($self, &$called) {
            $called++;
            $responseProphecy = $self->prophesize(ResponseInterface::class);
            return $responseProphecy->reveal();
        };
        $mw->setFailureHandler($handler);

        $requestProphecy = $this->prophesize(ServerRequestInterface::class);
        $requestProphecy
            ->getMethod()
            ->willReturn('POST')
            ->shouldBeCalledOnce();

        $requestProphecy
            ->withAttribute(Argument::type('string'), Argument::type('string'))
            ->willReturn($requestProphecy->reveal())
            ->shouldBeCalledTimes(2);

        $requestProphecy
            ->getParsedBody()
            ->willReturn([])
            ->shouldBeCalledOnce();

        $requestHandlerProphecy = $this->prophesize(RequestHandlerInterface::class);

        $mw->process($requestProphecy->reveal(), $requestHandlerProphecy->reveal());
        $this->assertEquals(1, $called);
    }

    public function testDefaultFailureHandler()
    {
        $streamProphecy = $this->prophesize(StreamInterface::class);
        $streamProphecy
            ->write('Failed CSRF check!')
            ->shouldBeCalledOnce();

        $responseProphecy = $this->prophesize(ResponseInterface::class);

        $responseProphecy
            ->getBody()
            ->willReturn($streamProphecy->reveal())
            ->shouldBeCalledOnce();

        $responseProphecy
            ->withStatus(400)
            ->willReturn($responseProphecy->reveal())
            ->shouldBeCalledOnce();

        $responseProphecy
            ->withHeader('Content-Type', 'text/plain')
            ->willReturn($responseProphecy->reveal())
            ->shouldBeCalledOnce();

        $responseProphecy
            ->withBody($streamProphecy->reveal())
            ->willReturn($responseProphecy->reveal())
            ->shouldBeCalledOnce();

        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $responseFactoryProphecy
            ->createResponse()
            ->willReturn($responseProphecy->reveal());

        $storage = [];
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage);

        $requestProphecy = $this->prophesize(ServerRequestInterface::class);
        $requestProphecy
            ->getMethod()
            ->willReturn('POST')
            ->shouldBeCalledOnce();

        $requestProphecy
            ->withAttribute(Argument::type('string'), Argument::type('string'))
            ->willReturn($requestProphecy->reveal())
            ->shouldBeCalledTimes(2);

        $requestProphecy
            ->getParsedBody()
            ->willReturn([])
            ->shouldBeCalledOnce();

        $requestHandlerProphecy = $this->prophesize(RequestHandlerInterface::class);

        $response = $mw->process($requestProphecy->reveal(), $requestHandlerProphecy->reveal());
        $this->assertSame($response, $responseProphecy->reveal());
    }

    public function testValidateToken()
    {
        $storage = [
            'test_name' => 'value'
        ];
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage);

        $this->assertTrue($mw->validateToken('test_name', 'value'));

        $GLOBALS['function_exists_return'] = false;

        $this->assertTrue($mw->validateToken('test_name', 'value'));
    }

    public function testGetTokenNameAndValue()
    {
        $storage = [];
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage);

        $this->assertNull($mw->getTokenName());
        $this->assertNull($mw->getTokenValue());

        $loadLastKeyPairMethod = new ReflectionMethod($mw, 'loadLastKeyPair');
        $loadLastKeyPairMethod->setAccessible(true);
        $loadLastKeyPairMethod->invoke($mw);

        $storage = [
            'test_name' => 'value',
        ];
        $mw->setStorage($storage);
        $loadLastKeyPairMethod->invoke($mw);

        $this->assertEquals('test_name', $mw->getTokenName());
        $this->assertEquals('value', $mw->getTokenValue());
    }

    public function testGetPersistentTokenMode()
    {
        $storage = [];
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage, null, 200, 16, true);

        $this->assertTrue($mw->getPersistentTokenMode());
    }

    public function testGetTokenNameKeyAndValue()
    {
        $storage = [];
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage);

        $this->assertEquals('test_name', $mw->getTokenNameKey());
        $this->assertEquals('test_value', $mw->getTokenValueKey());
    }

    public function testRemoveTokenFromStorage()
    {
        $storage = [
            'test_name' => 'value',
        ];
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage);

        $removeTokenFromStorageMethod = new ReflectionMethod($mw, 'removeTokenFromStorage');
        $removeTokenFromStorageMethod->setAccessible(true);
        $removeTokenFromStorageMethod->invoke($mw, 'test_name');

        $this->assertArrayNotHasKey('test_name', $storage);
    }

    public function testEnforceStorageLimitWithArray()
    {
        $storage = [
            'test_name' => 'value',
            'test_name2' => 'value2',
        ];
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage, null, 1);

        $enforceStorageLimitMethod = new ReflectionMethod($mw, 'enforceStorageLimit');
        $enforceStorageLimitMethod->setAccessible(true);
        $enforceStorageLimitMethod->invoke($mw);

        $this->assertArrayNotHasKey('test_name', $storage);
        $this->assertArrayHasKey('test_name2', $storage);
    }

    public function testNotEnforceStorageLimitWithArrayWhenLimitIsZero()
    {
        $initial_storage = $storage = [
            'test_name' => 'value',
            'test_name2' => 'value2',
        ];
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage, null, 0);

        $enforceStorageLimitMethod = new ReflectionMethod($mw, 'enforceStorageLimit');
        $enforceStorageLimitMethod->setAccessible(true);
        $enforceStorageLimitMethod->invoke($mw);

        $this->assertSame($initial_storage, $storage);
    }

    public function testEnforceStorageLimitWithIterator()
    {
        $storage = new ArrayIterator([
            'test_name' => 'value',
            'test_name2' => 'value',
        ]);
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage, null, 1);

        $enforceStorageLimitMethod = new ReflectionMethod($mw, 'enforceStorageLimit');
        $enforceStorageLimitMethod->setAccessible(true);
        $enforceStorageLimitMethod->invoke($mw);

        $this->assertArrayNotHasKey('test_name', $storage);
        $this->assertArrayHasKey('test_name2', $storage);
    }

    public function testTokenIsRemovedFromStorageWhenPersistentModeIsOff()
    {
        $storage = [
            'test_name' => 'test_value123',
        ];

        $response = $this->createMock(ResponseInterface::class);
        $requestHandler = $this->createMock(RequestHandlerInterface::class);
        $requestHandler->method('handle')->willReturn($response);

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);

        $handler = function () use ($response) {
            return $response;
        };

        $mw = new Guard($responseFactory, 'test', $storage, $handler);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects(self::once())->method('getMethod')->willReturn('POST');
        $request->expects(self::exactly(2))->method('withAttribute')->willReturn($request);
        $request->expects(self::once())->method('getParsedBody')->willReturn([
           'test_name' => 'test_name',
           'test_value' => 'test_value123',
        ]);

        $mw->process($request, $requestHandler);
        self::assertArrayNotHasKey('test_name', $storage);
    }


    public function testProcessAppendsNewTokensWhenPersistentTokenModeIsOff()
    {
        $storage = [];
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage);

        $responseProphecy = $this->prophesize(ResponseInterface::class);

        $requestProphecy = $this->prophesize(ServerRequestInterface::class);
        $requestProphecy
            ->getMethod()
            ->willReturn('GET')
            ->shouldBeCalledOnce();

        $requestProphecy
            ->withAttribute(Argument::type('string'), Argument::type('string'))
            ->willReturn($requestProphecy->reveal())
            ->shouldBeCalledTimes(2);

        $requestHandlerProphecy = $this->prophesize(RequestHandlerInterface::class);

        $requestHandlerProphecy
            ->handle($requestProphecy)
            ->willReturn($responseProphecy->reveal())
            ->shouldBeCalledOnce();

        $mw->process($requestProphecy->reveal(), $requestHandlerProphecy->reveal());
    }

    public function testProcessAppendsNewTokensWhenPersistentTokenModeIsOn()
    {
        $storage = [
            'test_name123' => 'test_value123',
        ];
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage, null, 200, 16, true);

        $responseProphecy = $this->prophesize(ResponseInterface::class);

        $requestProphecy = $this->prophesize(ServerRequestInterface::class);
        $requestProphecy
            ->getMethod()
            ->willReturn('GET')
            ->shouldBeCalledOnce();

        $requestProphecy
            ->withAttribute('test_name', 'test_name123')
            ->willReturn($requestProphecy->reveal())
            ->shouldBeCalledOnce();

        $requestProphecy
            ->withAttribute('test_value', 'test_value123')
            ->willReturn($requestProphecy->reveal())
            ->shouldBeCalledOnce();

        $requestHandlerProphecy = $this->prophesize(RequestHandlerInterface::class);

        $requestHandlerProphecy
            ->handle($requestProphecy)
            ->willReturn($responseProphecy->reveal())
            ->shouldBeCalledOnce();

        $mw->process($requestProphecy->reveal(), $requestHandlerProphecy->reveal());
    }
}
