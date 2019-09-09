<?php
/**
 * Slim Framework (https://slimframework.com)
 *
 * @license https://github.com/slimphp/Slim-Csrf/blob/master/LICENSE.md (MIT License)
 */

declare(strict_types=1);

namespace Slim\Csrf;

/**
 * Allows the stubbing of function_exists return value
 *
 * @param string $fn
 *
 * @return bool
 */
function function_exists(string $fn)
{
    if (isset($GLOBALS['function_exists_return'])) {
        return $GLOBALS['function_exists_return'];
    }

    return \function_exists($fn);
}
