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

$app->get('/foo', function ($req, $res, $args) {
    // CSRF token name and value
    $nameKey = $this->csrf->getTokenNameKey();
    $valueKey = $this->csrf->getTokenValueKey();
    $name = $req->getAttribute($nameKey);
    $value = $req->getAttribute($valueKey);

    // Render HTML form which POSTs to /bar with two hidden input fields for the
    // name and value:
    // <input type="hidden" name="<?= $nameKey ?>" value="<?= $name ?>">
    // <input type="hidden" name="<?= $valueKey ?>" value="<?= $value ?>">
});

$app->post('/bar', function ($req, $res, $args) {
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

$app->get('/api/myEndPoint',function ($req, $res, $args) {
    $nameKey = $this->csrf->getTokenNameKey();
    $valueKey = $this->csrf->getTokenValueKey();
    $name = $req->getAttribute($nameKey);
    $value = $req->getAttribute($valueKey);

    $tokenArray = [
        $nameKey => $name,
        $valueKey => $value
    ]
    
    return $response->write(json_encode($tokenArray));
})->add($container->get('csrf'));

$app->post('/api/myEndPoint',function ($req, $res, $args) {
    //Do my Things Securely!
})->add($container->get('csrf'));

$app->run();
```

## Token persistence

By default, `Slim\Csrf\Guard` will generate a fresh name/value pair after each request.  This is an important security measure for [certain situations](http://blog.ircmaxell.com/2013/02/preventing-csrf-attacks.html).  However, in many cases this is unnecessary, and [a single token throughout the user's session will suffice](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Synchronizer_.28CSRF.29_Tokens).  By using per-session requests it becomes easier, for example, to process AJAX requests without having to retrieve a new CSRF token (by reloading the page or making a separate request) after each request.  See issue #49.

To use persistent tokens, set the sixth parameter of the constructor to `true`.  No matter what, the token will be regenerated after a failed CSRF check.  In this case, you will probably want to detect this condition and instruct your users to reload the page in their legitimate browser tab (or automatically reload on the next failed request).

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
