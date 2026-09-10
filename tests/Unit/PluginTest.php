<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit;

use Composer\Composer;
use Composer\IO\NullIO;
use Composer\Plugin\Capability\CommandProvider as CommandProviderCapability;
use PHPUnit\Framework\TestCase;
use Remediate\Command\CommandProvider;
use Remediate\Command\DbBuildCommand;
use Remediate\Command\DbStatusCommand;
use Remediate\Command\RemediateCommand;
use Remediate\Plugin;

/**
 * The plugin's only job is to hand Composer the three commands; it hooks nothing else.
 */
final class PluginTest extends TestCase
{
    public function testExposesTheCommandProviderCapabilityOnly(): void
    {
        $plugin = new Plugin();
        self::assertSame([CommandProviderCapability::class => CommandProvider::class], $plugin->getCapabilities());

        $composer = new Composer();
        $io = new NullIO();
        $plugin->activate($composer, $io);
        $plugin->deactivate($composer, $io);
        $plugin->uninstall($composer, $io);
    }

    public function testProvidesTheThreeCommandsUnderTheirDocumentedNames(): void
    {
        $commands = (new CommandProvider())->getCommands();
        self::assertCount(3, $commands);
        self::assertInstanceOf(RemediateCommand::class, $commands[0]);
        self::assertInstanceOf(DbBuildCommand::class, $commands[1]);
        self::assertInstanceOf(DbStatusCommand::class, $commands[2]);
        self::assertSame(['remediate', 'remediate:db-build', 'remediate:db-status'], array_map(static fn ($c): string => (string) $c->getName(), $commands));
        self::assertSame(['remediate-db-build'], $commands[1]->getAliases());
        self::assertSame(['remediate-db-status'], $commands[2]->getAliases());
    }
}
