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

// Get container
$container = $app->getContainer();

// Register middleware
$container['csrf'] = function () {
    return new \Slim\Csrf\Guard();
};

$app->get('/foo', function ($req, $res, $args) {
    // CSRF token name and value
    $name = $req->getAttribute($this->csrf->getTokenNameKey());
    $value = $req->getAttribute($this->csrf->getTokenValueKey());

    // Render HTML form hidden input with this
    // CSRF token name and value.
});

$app->post('/bar', function ($req, $res, $args) {
    // CSRF protection successful if you reached
    // this far.
});

$app->run();
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
