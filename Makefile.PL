#!/usr/bin/perl
use 5.008;
use ExtUtils::MakeMaker;
WriteMakefile(
	NAME => 'DJabberd::Plugin::MAM',
	VERSION_FROM => 'lib/DJabberd/Plugin/MAM.pm',
	ABSTRACT_FROM => 'lib/DJabberd/Plugin/MAM.pm',
	PREREQ_PM => {
		'DJabberd' => '0.85',
		'DJabberd::Plugin::Carbons' => '0.0.1'
	},
	AUTHOR => 'Ruslan N. Marchenko <me@ruff.mobi>',
);
