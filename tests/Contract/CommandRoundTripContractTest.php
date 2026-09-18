<?php

declare(strict_types=1);

namespace Remediate\Tests\Contract;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Candidate\Candidate;
use Symfony\Component\Process\Process;

/**
 * Invariant: a command this tool prints, pasted into a shell, runs with the arguments it was built
 * from.
 *
 * Everything this tool produces is a command for someone else to run, so a rendered command that a
 * shell reads differently is not a report of what to do, it is a different instruction. The failure
 * is quiet in both directions: `--with acme/lib:>=1.2` unquoted makes the shell write a file called
 * `=1.2` and hand Composer no constraint at all, so the command appears to succeed and does something
 * else.
 *
 * Checked by actually running a shell and capturing the argument vector, because the question is what
 * a shell does with the string, and only a shell can answer it.
 */
final class CommandRoundTripContractTest extends TestCase
{
    /** @return iterable<string, array{list<string>}> */
    public static function argumentLists(): iterable
    {
        yield 'a plain update' => [['update', 'acme/lib', '-W']];
        yield 'a constraint with a greater-than' => [['update', 'acme/lib', '--with', 'acme/lib:>=1.2']];
        yield 'a constraint with a lower bound and an upper one' => [['update', 'acme/lib', '--with', 'acme/lib:>=1.2,<2.0']];
        yield 'an alternation' => [['update', 'acme/lib', '--with', 'acme/lib:>=5.4.31,<6.0.0 || >=6.3.8']];
        yield 'a caret' => [['require', 'acme/lib:^2.0', '--no-update']];
        yield 'a tilde' => [['require', 'acme/lib:~1.2.0', '--no-update']];
        yield 'an asterisk' => [['update', 'acme/*']];
        yield 'a semicolon' => [['update', 'acme/lib;whoami']];
        yield 'a backtick' => [['update', 'acme/lib`whoami`']];
        yield 'a dollar sign' => [['update', 'acme/$lib']];
        yield 'a single quote' => [["update", "acme/it's"]];
        yield 'a double quote' => [['update', 'acme/"lib"']];
        yield 'a space' => [['update', 'acme/lib two']];
        yield 'an ampersand' => [['update', 'acme/lib&&whoami']];
        yield 'a pipe' => [['update', 'acme/lib|whoami']];
        yield 'a newline' => [["update", "acme/lib\nwhoami"]];
    }

    /**
     * @param list<string> $arguments
     */
    #[DataProvider('argumentLists')]
    public function testARenderedCommandGivesBackTheArgumentsItWasBuiltFrom(array $arguments): void
    {
        $rendered = Candidate::render($arguments);
        self::assertStringStartsWith('composer ', $rendered);

        // `composer` is replaced by a function that writes down exactly what it was given, so what
        // comes back is the argument vector a real Composer would have received.
        $script = 'composer() { for a in "$@"; do printf "%s\0" "$a"; done; }; ' . $rendered;
        $process = new Process(['bash', '-c', $script]);
        $process->mustRun();

        $captured = array_values(array_filter(explode("\0", $process->getOutput()), static fn (string $s): bool => $s !== ''));
        self::assertSame($arguments, $captured, 'the shell read this differently from how it was built: ' . $rendered);
    }

    /**
     * @param list<string> $arguments
     */
    #[DataProvider('argumentLists')]
    public function testARenderedCommandCreatesNothingAndRunsNothing(array $arguments): void
    {
        // The other half: not only must the arguments survive, nothing else may happen on the way.
        // A redirection or a substitution that leaves a file behind or runs another program is the
        // failure this exists to catch.
        $directory = sys_get_temp_dir() . '/remediate-roundtrip-' . bin2hex(random_bytes(6));
        mkdir($directory, 0700, true);
        try {
            $script = 'composer() { :; }; whoami() { echo "SOMETHING RAN" > ran; }; ' . Candidate::render($arguments);
            (new Process(['bash', '-c', $script], $directory))->mustRun();

            $left = array_values(array_diff(scandir($directory) ?: [], ['.', '..']));
            self::assertSame([], $left, 'pasting this command into a shell left something behind: ' . Candidate::render($arguments));
        } finally {
            foreach (glob($directory . '/*') ?: [] as $file) {
                @unlink($file);
            }
            @rmdir($directory);
        }
    }
}
