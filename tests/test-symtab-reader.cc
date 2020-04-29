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
//
// Author: Matthias Maennich

/// @file
///
/// This program tests libabigail's symtab reader.

#include "lib/catch.hpp"

#include "abg-symtab-reader.h"

namespace abigail
{

using symtab_reader::symtab_filter;
using symtab_reader::symtab_filter_builder;

TEST_CASE("default symtab_filter matches anything",
	  "[symtab_reader, symtab_filter]")
{
  const symtab_filter	  filter;
  const elf_symbol_sptr symbol; // not initialized!
  CHECK(filter.matches(symbol));
}

TEST_CASE("default symtab_filter built with filter_builder matches anything",
	  "[symtab_reader, symtab_filter, symtab_filter_builder]")
{
  const symtab_filter filter = symtab_filter_builder();
  const elf_symbol_sptr symbol; // not initialized!
  CHECK(filter.matches(symbol));
}

} // namespace abigail
