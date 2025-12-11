# In an effort to make the build system customizable for downstream projects
# while still keeping it as easy as possible to merge changes back and forth
# between downstream and upstream, the build system is split into a few
# different files.
#
# We will try to make sure everything is well-commented to help you, but if you
# have any questions please don't hesitate to reach out!

## Include per-checkout configuration
#
# local.mk is a way to override settings on a per-checkout basis.  It is in the
# .gitignore and shouldn't be committed to git.
-include local.mk

# Project-specific overrides can go here.  Make sure to use ?= for assignment,
# though; otherwise you may overwrite a value from local.mk.  Using ?= in a
# Makefile means that the variable should only be set if it is not already set.
#
######################################################
### BEGIN PROJECT-SPECIFIC CONFIGURATION OVERRIDES ###
######################################################



####################################################
### END PROJECT-SPECIFIC CONFIGURATION OVERRIDES ###
####################################################

# Include common build system
#
# common.mk is basically the Makefile for the sample project.  It provides many
# points where you can hook into the logic to add your own functionality without
# actually modifying the code, which is important if you want to be able to
# easily pull in enhancements from the sample project!
include common.mk

# Project-specific customizations
#
# The end of this file is where you should try to put your project-specific
# changes; things like additional build targets, tools you want to install, etc.
#
# Please keep in mind that you can add additional dependencies to a target
# defined in common.mk. While you can't provide an additional recipe for an
# existing target, what you can do is provide a recipe for a new target and add
# that as a dependency.  For example, let's say you want something to be
# installed when the user runs `make install-tools`.  You can do something like:
#
# $(GO_BIN)/foobar:
# 	GOBIN="${GO_BIN}" go install github.com/foo/bar
#
# install-tools: $(GO_BIN)/foobar
#
#############################################
### BEGIN PROJECT-SPECIFIC CUSTOMIZATIONS ###
#############################################