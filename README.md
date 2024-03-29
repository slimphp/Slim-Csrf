# Slim Framework CSRF Protection

[![Build Status](https://travis-ci.org/slimphp/Slim-Csrf.svg?branch=master)](https://travis-ci.org/slimphp/Slim-Csrf)
[![Coverage Status](https://coveralls.io/repos/github/slimphp/Slim-Csrf/badge.svg?branch=master)](https://coveralls.io/github/slimphp/Slim-Csrf?branch=master)

This repository contains a Slim Framework CSRF protection PSR-15 middleware. CSRF protection applies to all unsafe HTTP requests (POST, PUT, DELETE, PATCH).

You can fetch the latest CSRF token's name and value from the Request object with its `getAttribute()` method. By default, the CSRF token's name is stored in the `csrf_name` attribute, and the CSRF token's value is stored in the `csrf_value` attribute.

## Install

Via Composer

``` bash
$ composer require slim/csrf
```

Requires Slim 4.0.0 or newer.

## Usage

In most cases you want to register Slim\Csrf for all routes, however, as it is middleware, you can also register it for a subset of routes.

### Register for all routes

```php
use DI\Container;
use Slim\Csrf\Guard;
use Slim\Factory\AppFactory;

require __DIR__ . '/vendor/autoload.php';

// Start PHP session
session_start();

// Create Container
$container = new Container();
AppFactory::setContainer($container);

// Create App
$app = AppFactory::create();
$responseFactory = $app->getResponseFactory();

// Register Middleware On Container
$container->set('csrf', function () use ($responseFactory) {
    return new Guard($responseFactory);
});

// Register Middleware To Be Executed On All Routes
$app->add('csrf');

$app->get('/foo', function ($request, $response, $args) {
    // CSRF token name and value
    $csrf = $this->get('csrf');
    $nameKey = $csrf->getTokenNameKey();
    $valueKey = $csrf->getTokenValueKey();
    $name = $request->getAttribute($nameKey);
    $value = $request->getAttribute($valueKey);

    /*
       Render HTML form which POSTs to /bar with two hidden input fields for the
       name and value:
       <input type="hidden" name="<?= $nameKey ?>" value="<?= $name ?>">
       <input type="hidden" name="<?= $valueKey ?>" value="<?= $value ?>">
     */
});

$app->post('/bar', function ($request, $response, $args) {
    // CSRF protection successful if you reached
    // this far.
});

$app->run();
```

### Register per route

```php
use DI\Container;
use Slim\Csrf\Guard;
use Slim\Factory\AppFactory;

require __DIR__ . '/vendor/autoload.php';

// Start PHP session
session_start();

// Create Container
$container = new Container();
AppFactory::setContainer($container);

// Create App
$app = AppFactory::create();
$responseFactory = $app->getResponseFactory();

// Register Middleware On Container
$container->set('csrf', function () use ($responseFactory) {
    return new Guard($responseFactory);
});

$app->get('/api/route',function ($request, $response, $args) {
    $csrf = $this->get('csrf');
    $nameKey = $csrf->getTokenNameKey();
    $valueKey = $csrf->getTokenValueKey();
    $name = $request->getAttribute($nameKey);
    $value = $request->getAttribute($valueKey);

    $tokenArray = [
        $nameKey => $name,
        $valueKey => $value
    ];
    
    return $response->write(json_encode($tokenArray));
})->add('csrf');

$app->post('/api/myEndPoint',function ($request, $response, $args) {
    //Do my Things Securely!
})->add('csrf');

$app->run();
```

### Manual usage

If you are willing to use `Slim\Csrf\Guard` outside a `Slim\App` or not as a middleware, be careful to validate the storage:

```php
use Slim\Csrf\Guard;
use Slim\Psr7\Factory\ResponseFactory;

// Start PHP session
session_start();

// Create Middleware
$responseFactory = new ResponseFactory(); // Note that you will need to import
$guard = new Guard($responseFactory);

// Generate new tokens
$csrfNameKey = $guard->getTokenNameKey();
$csrfValueKey = $guard->getTokenValueKey();
$keyPair = $guard->generateToken();

// Validate retrieved tokens
$guard->validateToken($_POST[$csrfNameKey], $_POST[$csrfValueKey]);
```

## Token persistence

By default, `Slim\Csrf\Guard` will generate a fresh name/value pair after each request.  This is an important security measure for [certain situations](http://blog.ircmaxell.com/2013/02/preventing-csrf-attacks.html).  However, in many cases this is unnecessary, and [a single token throughout the user's session will suffice](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Synchronizer_.28CSRF.29_Tokens).  By using per-session requests it becomes easier, for example, to process AJAX requests without having to retrieve a new CSRF token (by reloading the page or making a separate request) after each request.  See issue [#49](https://github.com/slimphp/Slim-Csrf/issues/49).

To use persistent tokens, set the sixth parameter of the constructor to `true`.  No matter what, the token will be regenerated after a failed CSRF check.  In this case, you will probably want to detect this condition and instruct your users to reload the page in their legitimate browser tab (or automatically reload on the next failed request).

### Accessing the token pair in templates (Twig, etc)

In many situations, you will want to access the token pair without needing to go through the request object.  In these cases, you can use `getTokenName()` and `getTokenValue()` directly on the `Guard` middleware instance.  This can be useful, for example in a [Twig extension](https://twig.symfony.com/doc/2.x/advanced.html#creating-an-extension):

```php
use Slim\Csrf\Guard;

class CsrfExtension extends \Twig\Extension\AbstractExtension implements \Twig\Extension\GlobalsInterface
{
    /**
     * @var Guard
     */
    protected $csrf;
    
    public function __construct(Guard $csrf)
    {
        $this->csrf = $csrf;
    }

    public function getGlobals()
    {
        // CSRF token name and value
        $csrfNameKey = $this->csrf->getTokenNameKey();
        $csrfValueKey = $this->csrf->getTokenValueKey();
        $csrfName = $this->csrf->getTokenName();
        $csrfValue = $this->csrf->getTokenValue();
        
        return [
            'csrf'   => [
                'keys' => [
                    'name'  => $csrfNameKey,
                    'value' => $csrfValueKey
                ],
                'name'  => $csrfName,
                'value' => $csrfValue
            ]
        ];
    }
}
```

Once you have registered your extension, you may access the token pair in any template:

```twig
<input type="hidden" name="{{csrf.keys.name}}" value="{{csrf.name}}">
<input type="hidden" name="{{csrf.keys.value}}" value="{{csrf.value}}">
```


## Handling validation failure

By default, `Slim\Csrf\Guard` will return a Response with a 400 status code and
a simple plain text error message.

To override this, provide a callable as the third parameter to the constructor
or via `setFailureHandler()`. This callable has the same signature as
middleware: `function($request, $handler)` and must return a Response.

For example:

```php
use Slim\Csrf\Guard;
use Slim\Psr7\Factory\ResponseFactory;

$responseFactory = new ResponseFactory();
$guard = new Guard($responseFactory);
$guard->setFailureHandler(function (ServerRequestInterface $request, RequestHandlerInterface $handler) {
    $request = $request->withAttribute("csrf_status", false);
    return $handler->handle($request);
});
```

In this example, an attribute is set on the request object that can then be
checked in subsequent middleware or the route callable using:

```php
if (false === $request->getAttribute('csrf_status')) {
    // display suitable error here
} else {
    // successfully passed CSRF check
}
```

## Testing

``` bash
$ phpunit
```

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security

If you discover any security related issues, please email security@slimframework.com instead of using the issue tracker.

## Credits

- [Josh Lockhart](https://github.com/codeguy)
- [All Contributors](../../contributors)
- Initial inspiration from [OWASP](https://www.owasp.org/index.php/PHP_CSRF_Guard)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
