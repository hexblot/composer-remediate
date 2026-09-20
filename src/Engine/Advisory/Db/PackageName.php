<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

/**
 * The one definition of "a package identity a lock could hold".
 *
 * Every advisory source names the packages it is about, and each of them can be malformed in the
 * same way: a name that is not a Composer package name at all. Such a name is not a package this
 * found no fix for, and not a package from another ecosystem; it is an advisory whose subject could
 * not be read. Keeping it would file an affected range under an identity no locked package can ever
 * match, which is coverage lost in the quietest way there is, because the record is in the database
 * and looks like every other one.
 */
final class PackageName
{
    /**
     * Composer's own package-name syntax, copied from `ValidatingArrayLoader::hasPackageNamingError()`
     * so that what counts as a name here is what counts as one in a lock file.
     *
     * That method itself is not used: besides the syntax it reports upper case as a deprecation and
     * rejects a handful of reserved words, and advisory feeds do carry names like `Acme/Lib` for
     * packages Packagist resolves case-insensitively. Those are readable identities, so only the
     * syntax is taken from it.
     */
    private const SYNTAX = '{^[a-z0-9](?:[_.-]?[a-z0-9]++)*+/[a-z0-9](?:(?:[_.]|-{1,2})?[a-z0-9]++)*+$}iD';

    /**
     * The name as a lock file would hold it, or null when the value is not a package name at all:
     * absent, not text, empty, or text no package could be called.
     */
    public static function canonical(mixed $name): ?string
    {
        if (!is_string($name) || $name === '') {
            return null;
        }

        return preg_match(self::SYNTAX, $name) === 1 ? strtolower($name) : null;
    }
}
