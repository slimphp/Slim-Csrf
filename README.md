# Slim Framework CSRF Protection

[![Build Status](https://travis-ci.org/slimphp/Slim-Csrf.svg?branch=master)](https://travis-ci.org/slimphp/Slim-Csrf)

This repository contains a Slim Framework CSRF protection middleware. CSRF protection applies to all unsafe HTTP requests (POST, PUT, DELETE, PATCH).

You can fetch the latest CSRF token's name and value from the Request object with its `getAttribute()` method. By default, the CSRF token's name is stored in the `csrf_name` attribute, and the CSRF token's value is stored in the `csrf_value` attribute.

## Install

Via Composer

``` bash
$ composer require slim/csrf
```

Requires Slim 3.0.0 or newer.

## Usage

In most cases you want to register Slim\Csrf for all routes, however,
as it is middleware, you can also register it for a subset of routes.


### Register for all routes

```php
// Start PHP session
session_start();

$app = new \Slim\App();

// Register with container
$container = $app->getContainer();
$container['csrf'] = function ($c) {
    return new \Slim\Csrf\Guard;
};

// Register middleware for all routes
// If you are implementing per-route checks you must not add this
$app->add($container->get('csrf'));

$app->get('/foo', function ($request, $response, $args) {
    // CSRF token name and value
    $nameKey = $this->csrf->getTokenNameKey();
    $valueKey = $this->csrf->getTokenValueKey();
    $name = $request->getAttribute($nameKey);
    $value = $request->getAttribute($valueKey);

    // Render HTML form which POSTs to /bar with two hidden input fields for the
    // name and value:
    // <input type="hidden" name="<?= $nameKey ?>" value="<?= $name ?>">
    // <input type="hidden" name="<?= $valueKey ?>" value="<?= $value ?>">
});

$app->post('/bar', function ($request, $response, $args) {
    // CSRF protection successful if you reached
    // this far.
});

$app->run();
```

### Register per route

```php
// Start PHP session
session_start();

$app = new \Slim\App();

// Register with container
$container = $app->getContainer();
$container['csrf'] = function ($c) {
    return new \Slim\Csrf\Guard;
};

$app->get('/api/myEndPoint',function ($request, $response, $args) {
    $nameKey = $this->csrf->getTokenNameKey();
    $valueKey = $this->csrf->getTokenValueKey();
    $name = $request->getAttribute($nameKey);
    $value = $request->getAttribute($valueKey);

    $tokenArray = [
        $nameKey => $name,
        $valueKey => $value
    ]
    
    return $response->write(json_encode($tokenArray));
})->add($container->get('csrf'));

$app->post('/api/myEndPoint',function ($request, $response, $args) {
    //Do my Things Securely!
})->add($container->get('csrf'));

$app->run();
```

### Manual usage

If you are willing to use `Slim\Csrf\Guard` outside a `Slim\App` or not as a middleware, be careful to validate the storage:

```php
// Start PHP session
session_start();

$slimGuard = new \Slim\Csrf\Guard;
$slimGuard->validateStorage();

// Generate new tokens
$csrfNameKey = $slimGuard->getTokenNameKey();
$csrfValueKey = $slimGuard->getTokenValueKey();
$keyPair = $slimGuard->generateToken();

// Validate retrieved tokens
$slimGuard->validateToken($_POST[$csrfNameKey], $_POST[$csrfValueKey]);
```

## Token persistence

By default, `Slim\Csrf\Guard` will generate a fresh name/value pair after each request.  This is an important security measure for [certain situations](http://blog.ircmaxell.com/2013/02/preventing-csrf-attacks.html).  However, in many cases this is unnecessary, and [a single token throughout the user's session will suffice](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Synchronizer_.28CSRF.29_Tokens).  By using per-session requests it becomes easier, for example, to process AJAX requests without having to retrieve a new CSRF token (by reloading the page or making a separate request) after each request.  See issue #49.

To use persistent tokens, set the sixth parameter of the constructor to `true`.  No matter what, the token will be regenerated after a failed CSRF check.  In this case, you will probably want to detect this condition and instruct your users to reload the page in their legitimate browser tab (or automatically reload on the next failed request).


### Accessing the token pair in templates (Twig, etc)

In many situations, you will want to access the token pair without needing to go through the request object.  In these cases, you can use `getTokenName()` and `getTokenValue()` directly on the `Guard` middleware instance.  This can be useful, for example in a [Twig extension](http://twig.sensiolabs.org/doc/advanced.html#creating-an-extension):

```php
class CsrfExtension extends \Twig_Extension
{

    /**
     * @var \Slim\Csrf\Guard
     */
    protected $csrf;
    
    public function __construct(\Slim\Csrf\Guard $csrf)
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

    public function getName()
    {
        return 'slim/csrf';
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
or via `setFailureCallable()`. This callable has the same signature as
middleware: `function($request, $response, $next)` and must return a Response.

For example:

```php
$container['csrf'] = function ($c) {
    $guard = new \Slim\Csrf\Guard();
    $guard->setFailureCallable(function ($request, $response, $next) {
        $request = $request->withAttribute("csrf_status", false);
        return $next($request, $response);
    });
    return $guard;
};
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
