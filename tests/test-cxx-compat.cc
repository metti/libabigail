// -*- Mode: C++ -*-
//
// Copyright (C) 2020 Google, Inc.
//
// This file is part of the GNU Application Binary Interface Generic
// Analysis and Instrumentation Library (libabigail).  This library is
// free software; you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the
// Free Software Foundation; either version 3, or (at your option) any
// later version.

// This library is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Lesser Public License for more details.

// You should have received a copy of the GNU Lesser General Public
// License along with this program; see the file COPYING-LGPLV3.  If
// not, see <http://www.gnu.org/licenses/>.

// Author: Matthias Maennich

/// @file
///
/// This program tests libabigail's CXX compatibility layer.

#include "lib/catch.hpp"

#include "abg-cxx-compat.h"

using abg_compat::optional;

TEST_CASE("OptionalConstruction", "[abg_compat::optional]")
{
  optional<bool> opt1;
  REQUIRE_FALSE(opt1.has_value());

  optional<bool> opt2(true);
  REQUIRE(opt2.has_value());
  CHECK(opt2.value() == true);

  optional<bool> opt3(false);
  REQUIRE(opt3.has_value());
  CHECK(opt3.value() == false);
}

TEST_CASE("OptionalValue", "[abg_compat::optional]")
{
  optional<bool> opt;
  REQUIRE_FALSE(opt.has_value());
  REQUIRE_THROWS(opt.value());

  opt = true;
  REQUIRE_NOTHROW(opt.value());
  CHECK(opt.value() == true);
}

TEST_CASE("OptionalValueOr", "[abg_compat::optional]")
{
  optional<std::string> opt;
  REQUIRE_FALSE(opt.has_value());

  const std::string& mine = "mine";
  // Ensure we get a copy of our own value.
  CHECK(opt.value_or(mine) == mine);

  // Now set the value
  const std::string& other = "other";
  opt = other;
  CHECK(opt.value_or(mine) != mine);
  CHECK(opt.value_or(mine) == other);
}

TEST_CASE("OptionalDeref", "[abg_compat::optional]")
{
  optional<std::string> opt("asdf");
  REQUIRE(opt.has_value());

  CHECK(*opt == "asdf");
  CHECK(opt->size() == 4);
}
