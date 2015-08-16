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

```php
// Start PHP session
session_start();

$app = new \Slim\App();

// Register with container
$container = $app->getContainer();
$container['csrf'] = function ($c) {
    return new \Slim\Csrf\Guard;
};

// Register middleware
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

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
