// -*- Mode: C++ -*-
//
// Copyright (C) 2013-2020 Red Hat, Inc.
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
/// This contains the definition of the symtab reader

#include <algorithm>
#include <iostream>

#include "abg-cxx-compat.h"
#include "abg-elf-helpers.h"
#include "abg-fwd.h"
#include "abg-internal.h"
#include "abg-tools-utils.h"

ABG_BEGIN_EXPORT_DECLARATIONS
#include "abg-symtab-reader.h"
ABG_END_EXPORT_DECLARATIONS

namespace abigail
{

namespace symtab_reader
{

/// symtab_filter implementations

bool
symtab_filter::matches(const elf_symbol_sptr& symbol) const
{
  if (functions_ && *functions_ != symbol->is_function())
    return false;
  if (variables_ && *variables_ != symbol->is_variable())
    return false;
  if (public_symbols_ && *public_symbols_ != symbol->is_public())
    return false;
  if (undefined_symbols_ && *undefined_symbols_ == symbol->is_defined())
    return false;
  if (kernel_symbols_ && *kernel_symbols_ != symbol->is_in_ksymtab())
    return false;

  return true;
}

/// symtab implementations

symtab_filter_builder
symtab::make_filter() const
{
  symtab_filter_builder builder;
  builder.public_symbols();
  if (is_kernel_binary_)
    builder.kernel_symbols();
  return builder;
}

const elf_symbols&
symtab::lookup_symbol(const std::string& name) const
{
  static const elf_symbols empty_result;
  const name_symbol_map_type::const_iterator it = name_symbol_map_.find(name);
  if (it != name_symbol_map_.end())
    {
      return it->second;
    }
  return empty_result;
}

const elf_symbol_sptr&
symtab::lookup_symbol(GElf_Addr symbol_addr) const
{
  static const elf_symbol_sptr empty_result;
  const addr_symbol_map_type::const_iterator it =
      addr_symbol_map_.find(symbol_addr);
  if (it != addr_symbol_map_.end())
    {
      return it->second;
    }
  return empty_result;
}

/// A symbol sorting functor.
static struct
{
  bool
  operator()(const elf_symbol_sptr& left, const elf_symbol_sptr& right)
  { return left->get_id_string() < right->get_id_string(); }
} symbol_sort;

symtab_sptr
symtab::load(Elf*	      elf_handle,
	     ir::environment* env,
	     symbol_predicate is_suppressed)
{
  ABG_ASSERT(elf_handle);
  ABG_ASSERT(env);

  symtab_sptr result(new symtab);
  if (!result->load_(elf_handle, env, is_suppressed))
    return symtab_sptr();

  return result;
}

symtab_sptr
symtab::load(string_elf_symbols_map_sptr function_symbol_map,
	     string_elf_symbols_map_sptr variables_symbol_map)
{
  symtab_sptr result(new symtab);
  if (!result->load_(function_symbol_map, variables_symbol_map))
    return symtab_sptr();

  return result;
}

symtab::symtab() : is_kernel_binary_(false), has_ksymtab_entries_(false) {}

bool
symtab::load_(Elf*	       elf_handle,
	      ir::environment* env,
	      symbol_predicate is_suppressed)
{

  Elf_Scn* symtab_section = elf_helpers::find_symbol_table_section(elf_handle);
  if (!symtab_section)
    {
      std::cerr << "No symbol table found: Skipping symtab load.\n";
      return false;
    }

  GElf_Shdr symtab_sheader;
  gelf_getshdr(symtab_section, &symtab_sheader);

  // check for bogus section header
  if (symtab_sheader.sh_entsize == 0)
    {
      std::cerr << "Invalid symtab header found: Skipping symtab load.\n";
      return false;
    }

  const size_t number_syms =
      symtab_sheader.sh_size / symtab_sheader.sh_entsize;

  Elf_Data* symtab = elf_getdata(symtab_section, 0);
  if (!symtab)
    {
      std::cerr << "Could not load elf symtab: Skipping symtab load.\n";
      return false;
    }

  const bool is_kernel = elf_helpers::is_linux_kernel(elf_handle);
  abg_compat::unordered_set<std::string> exported_kernel_symbols;

  for (size_t i = 0; i < number_syms; ++i)
    {
      GElf_Sym *sym, sym_mem;
      sym = gelf_getsym(symtab, i, &sym_mem);
      if (!sym)
	{
	  std::cerr << "Could not load symbol with index " << i
		    << ": Skipping symtab load.\n";
	  return false;
	}

      const char* name_str =
	  elf_strptr(elf_handle, symtab_sheader.sh_link, sym->st_name);

      // no name, no game
      if (!name_str)
	continue;

      // Handle ksymtab entries. Every symbol entry that starts with __ksymtab_
      // indicates that the symbol in question is exported through ksymtab. We
      // do not know whether this is ksymtab_gpl or ksymtab, but that is good
      // enough for now.
      //
      // We could follow up with this entry:
      //
      // symbol_value -> ksymtab_entry in either ksymtab_gpl or ksymtab
      //              -> addr/name/namespace (in case of PREL32: offset)
      //
      // That way we could also detect ksymtab<>ksymtab_gpl changes or changes
      // of the symbol namespace.
      //
      // As of now this lookup is fragile, as occasionally ksymtabs are empty
      // (seen so far for kernel modules and LTO builds). Hence we stick to the
      // fairly safe assumption that ksymtab exported entries are having an
      // appearence as __ksymtab_<symbol> in the symtab.
      const std::string name = name_str;
      if (is_kernel && name.rfind("__ksymtab_", 0) == 0)
	{
	  ABG_ASSERT(exported_kernel_symbols.insert(name.substr(10)).second);
	  continue;
	}

      // filter out uninteresting entries and only keep functions/variables for
      // now. The rest might be interesting in the future though.
      const int sym_type = GELF_ST_TYPE(sym->st_info);
      if (!(sym_type == STT_FUNC
	    || sym_type == STT_GNU_IFUNC
	    // If the symbol is for an OBJECT, the index of the
	    // section it refers to cannot be absolute.
	    // Otherwise that OBJECT is not a variable.
	    || (sym_type == STT_OBJECT && sym->st_shndx != SHN_ABS)
	    || sym_type == STT_TLS))
	continue;

      const bool sym_is_defined = sym->st_shndx != SHN_UNDEF;
      // this occurs in relocatable files.
      const bool sym_is_common = sym->st_shndx == SHN_COMMON;

      elf_symbol::version ver;
      elf_helpers::get_version_for_symbol(elf_handle, i, sym_is_defined, ver);

      const elf_symbol_sptr& symbol_sptr = elf_symbol::create(
	  env, i, sym->st_size, name,
	  elf_helpers::stt_to_elf_symbol_type(GELF_ST_TYPE(sym->st_info)),
	  elf_helpers::stb_to_elf_symbol_binding(GELF_ST_BIND(sym->st_info)),
	  sym_is_defined, sym_is_common, ver,
	  elf_helpers::stv_to_elf_symbol_visibility(
	      GELF_ST_VISIBILITY(sym->st_other)),
	  false); // TODO: is_linux_strings_cstr

      // We do not take suppressed symbols into our symbol vector to avoid
      // accidental leakage. But we ensure supressed symbols are otherwise set
      // up for lookup.
      if (!(is_suppressed && is_suppressed(symbol_sptr)))
	// add to the symbol vector
	symbols_.push_back(symbol_sptr);
      else
	symbol_sptr->set_is_suppressed(true);

      // add to the name->symbol lookup
      name_symbol_map_[name].push_back(symbol_sptr);

      // add to the addr->symbol lookup
      if (symbol_sptr->is_common_symbol())
	{
	  const name_symbol_map_type::iterator it =
	      name_symbol_map_.find(name);
	  ABG_ASSERT(it != name_symbol_map_.end());
	  const elf_symbols& common_sym_instances = it->second;
	  ABG_ASSERT(!common_sym_instances.empty());
	  if (common_sym_instances.size() > 1)
	    {
	      elf_symbol_sptr main_common_sym = common_sym_instances[0];
	      ABG_ASSERT(main_common_sym->get_name() == name);
	      ABG_ASSERT(main_common_sym->is_common_symbol());
	      ABG_ASSERT(symbol_sptr.get() != main_common_sym.get());
	      main_common_sym->add_common_instance(symbol_sptr);
	    }
	}
      else if (symbol_sptr->is_defined())
	{
	  const GElf_Addr symbol_value =
	      elf_helpers::maybe_adjust_et_rel_sym_addr_to_abs_addr(elf_handle,
								    sym);

	  const std::pair<addr_symbol_map_type::const_iterator, bool> result =
	      addr_symbol_map_.insert(
		  std::make_pair(symbol_value, symbol_sptr));
	  if (!result.second)
	    result.first->second->get_main_symbol()->add_alias(symbol_sptr);
	}
    }

  is_kernel_binary_ = elf_helpers::is_linux_kernel(elf_handle);

  // Now apply the ksymtab_exported attribute to the symbols we collected.
  for (abg_compat::unordered_set<std::string>::const_iterator
	   it = exported_kernel_symbols.begin(),
	   en = exported_kernel_symbols.end();
       it != en; ++it)
    {
      const name_symbol_map_type::const_iterator r =
	  name_symbol_map_.find(*it);
      if (r == name_symbol_map_.end())
	continue;

      for (elf_symbols::const_iterator sym_it = r->second.begin(),
				       sym_end = r->second.end();
	   sym_it != sym_end; ++sym_it)
	{
	  if ((*sym_it)->is_public())
	    (*sym_it)->set_is_in_ksymtab(true);
	}
      has_ksymtab_entries_ = true;
    }

  // sort the symbols for deterministic output
  std::sort(symbols_.begin(), symbols_.end(), symbol_sort);

  return true;
}

bool
symtab::load_(string_elf_symbols_map_sptr function_symbol_map,
	     string_elf_symbols_map_sptr variables_symbol_map)

{
  if (function_symbol_map)
    for (string_elf_symbols_map_type::const_iterator
	     it = function_symbol_map->begin(),
	     end = function_symbol_map->end();
	 it != end; ++it)
      {
	symbols_.insert(symbols_.end(), it->second.begin(), it->second.end());
	ABG_ASSERT(name_symbol_map_.insert(*it).second);
      }

  if (variables_symbol_map)
    for (string_elf_symbols_map_type::const_iterator
	     it = variables_symbol_map->begin(),
	     end = variables_symbol_map->end();
	 it != end; ++it)
      {
	symbols_.insert(symbols_.end(), it->second.begin(), it->second.end());
	ABG_ASSERT(name_symbol_map_.insert(*it).second);
      }

  // sort the symbols for deterministic output
  std::sort(symbols_.begin(), symbols_.end(), symbol_sort);

  return true;
}

} // end namespace symtab_reader
} // end namespace abigail
