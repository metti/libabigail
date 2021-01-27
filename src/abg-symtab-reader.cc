// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// -*- Mode: C++ -*-
//
// Copyright (C) 2013-2020 Red Hat, Inc.
// Copyright (C) 2020 Google, Inc.
//
// Author: Matthias Maennich

/// @file
///
/// This contains the definition of the symtab reader

#include <algorithm>
#include <iostream>
#include <unordered_set>

#include "abg-elf-helpers.h"
#include "abg-fwd.h"
#include "abg-internal.h"
#include "abg-tools-utils.h"

// Though this is an internal header, we need to export the symbols to be able
// to test this code.  TODO: find a way to export symbols just for unit tests.
ABG_BEGIN_EXPORT_DECLARATIONS
#include "abg-symtab-reader.h"
ABG_END_EXPORT_DECLARATIONS

namespace abigail
{

namespace symtab_reader
{

/// symtab_filter implementations

/// Determine whether a symbol is matching the filter criteria of this filter
/// object. In terms of a filter functionality, you would _not_ filter out
/// this symbol if it passes this (i.e. returns true).
///
/// @param symbol The Elf symbol under test.
///
/// @return whether the symbol matches all relevant / required criteria
bool
symtab_filter::matches(const elf_symbol& symbol) const
{
  if (functions_ && *functions_ != symbol.is_function())
    return false;
  if (variables_ && *variables_ != symbol.is_variable())
    return false;
  if (public_symbols_ && *public_symbols_ != symbol.is_public())
    return false;
  if (undefined_symbols_ && *undefined_symbols_ == symbol.is_defined())
    return false;
  if (kernel_symbols_ && *kernel_symbols_ != symbol.is_in_ksymtab())
    return false;

  return true;
}

/// symtab implementations

/// Obtain a suitable default filter for iterating this symtab object.
///
/// The symtab_filter obtained is populated with some sensible default
/// settings, such as public_symbols(true) and kernel_symbols(true) if the
/// binary has been identified as Linux Kernel binary.
///
/// @return a symtab_filter with sensible populated defaults
symtab_filter
symtab::make_filter() const
{
  symtab_filter filter;
  filter.set_public_symbols();
  if (is_kernel_binary_)
    filter.set_kernel_symbols();
  return filter;
}

/// Get a vector of symbols that are associated with a certain name
///
/// @param name the name the symbols need to match
///
/// @return a vector of symbols, empty if no matching symbols have been found
const elf_symbols&
symtab::lookup_symbol(const std::string& name) const
{
  static const elf_symbols empty_result;
  const auto it = name_symbol_map_.find(name);
  if (it != name_symbol_map_.end())
      return it->second;
  return empty_result;
}

/// Lookup a symbol by its address
///
/// @param symbol_addr the starting address of the symbol
///
/// @return a symbol if found, else an empty sptr
const elf_symbol_sptr&
symtab::lookup_symbol(GElf_Addr symbol_addr) const
{
  static const elf_symbol_sptr empty_result;
  const auto addr_it = addr_symbol_map_.find(symbol_addr);
  if (addr_it != addr_symbol_map_.end())
    return addr_it->second;
  else
    {
      const auto entry_it = entry_addr_symbol_map_.find(symbol_addr);
      if (entry_it != entry_addr_symbol_map_.end())
	return entry_it->second;
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

/// Construct a symtab object and instantiate from an ELF handle. Also pass
/// in an ir::environment handle to interact with the context we are living
/// in. If specified, the symbol_predicate will be respected when creating
/// the full vector of symbols.
symtab_ptr
symtab::load(Elf*	      elf_handle,
	     ir::environment* env,
	     symbol_predicate is_suppressed)
{
  ABG_ASSERT(elf_handle);
  ABG_ASSERT(env);

  symtab_ptr result(new symtab);
  if (!result->load_(elf_handle, env, is_suppressed))
    return {};

  return result;
}

/// Construct a symtab object from existing name->symbol lookup maps.
/// They were possibly read from a different representation (XML maybe).
symtab_ptr
symtab::load(string_elf_symbols_map_sptr function_symbol_map,
	     string_elf_symbols_map_sptr variables_symbol_map)
{
  symtab_ptr result(new symtab);
  if (!result->load_(function_symbol_map, variables_symbol_map))
    return {};

  return result;
}

symtab::symtab() : is_kernel_binary_(false), has_ksymtab_entries_(false) {}

/// Load the symtab representation from an Elf binary presented to us by an
/// Elf* handle.
///
/// This method iterates over the entries of .symtab and collects all
/// interesting symbols (functions and variables).
///
/// In case of a Linux Kernel binary, it also collects information about the
/// symbols exported via EXPORT_SYMBOL in the Kernel that would then end up
/// having a corresponding __ksymtab entry.
///
/// Symbols that are suppressed will be omitted from the symbols_ vector, but
/// still be discoverable through the name->symbol and addr->symbol lookup
/// maps.
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
  std::unordered_set<std::string> exported_kernel_symbols;

  const bool is_ppc64 = elf_helpers::architecture_is_ppc64(elf_handle);

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

      const char* const name_str =
	  elf_strptr(elf_handle, symtab_sheader.sh_link, sym->st_name);

      // no name, no game
      if (!name_str)
	continue;

      const std::string name = name_str;
      if (name.empty())
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
	  const auto it = name_symbol_map_.find(name);
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

	  if (is_ppc64 && symbol_sptr->is_function())
	    update_function_entry_address_symbol_map(elf_handle, sym,
						     symbol_sptr);

	  const auto result =
	    addr_symbol_map_.emplace(symbol_value, symbol_sptr);
	  if (!result.second)
	    result.first->second->get_main_symbol()->add_alias(symbol_sptr);
	}
    }

  is_kernel_binary_ = elf_helpers::is_linux_kernel(elf_handle);

  // Now apply the ksymtab_exported attribute to the symbols we collected.
  for (const auto& symbol : exported_kernel_symbols)
    {
      const auto r = name_symbol_map_.find(symbol);
      if (r == name_symbol_map_.end())
	continue;

      for (const auto& elf_symbol : r->second)
	  if (elf_symbol->is_public())
	    elf_symbol->set_is_in_ksymtab(true);
      has_ksymtab_entries_ = true;
    }

  // sort the symbols for deterministic output
  std::sort(symbols_.begin(), symbols_.end(), symbol_sort);

  return true;
}

/// Load the symtab representation from a function/variable lookup map pair.
///
/// This method assumes the lookup maps are correct and sets up the data
/// vector as well as the name->symbol lookup map. The addr->symbol lookup
/// map cannot be set up in this case.
bool
symtab::load_(string_elf_symbols_map_sptr function_symbol_map,
	     string_elf_symbols_map_sptr variables_symbol_map)

{
  if (function_symbol_map)
    for (const auto& symbol_map_entry : *function_symbol_map)
      {
	symbols_.insert(symbols_.end(), symbol_map_entry.second.begin(),
			symbol_map_entry.second.end());
	ABG_ASSERT(name_symbol_map_.insert(symbol_map_entry).second);
      }

  if (variables_symbol_map)
    for (const auto& symbol_map_entry : *variables_symbol_map)
      {
	symbols_.insert(symbols_.end(), symbol_map_entry.second.begin(),
			symbol_map_entry.second.end());
	ABG_ASSERT(name_symbol_map_.insert(symbol_map_entry).second);
      }

  // sort the symbols for deterministic output
  std::sort(symbols_.begin(), symbols_.end(), symbol_sort);

  return true;
}

void
symtab::update_function_entry_address_symbol_map(
    Elf*		   elf_handle,
    GElf_Sym*		   native_symbol,
    const elf_symbol_sptr& symbol_sptr)
{

  // For ppc64 ELFv1 binaries, we need to build a function entry point address
  // -> function symbol map. This is in addition to the function pointer ->
  // symbol map.  This is because on ppc64 ELFv1, a function pointer is
  // different from a function entry point address.
  //
  // On ppc64 ELFv1, the DWARF DIE of a function references the address of the
  // entry point of the function symbol; whereas the value of the function
  // symbol is the function pointer. As these addresses are different, if I we
  // want to get to the symbol of a function from its entry point address (as
  // referenced by DWARF function DIEs) we must have the two maps I mentionned
  // right above.
  //
  // In other words, we need a map that associates a function entry point
  // address with the symbol of that function, to be able to get the function
  // symbol that corresponds to a given function DIE, on ppc64.
  //
  // The value of the function pointer (the value of the symbol) usually refers
  // to the offset of a table in the .opd section.  But sometimes, for a symbol
  // named "foo", the corresponding symbol named ".foo" (note the dot before
  // foo) which value is the entry point address of the function; that entry
  // point address refers to a region in the .text section.
  //
  // So we are only interested in values of the symbol that are in the .opd
  // section.
  const GElf_Addr fn_desc_addr = native_symbol->st_value;
  const GElf_Addr fn_entry_point_addr =
    elf_helpers::lookup_ppc64_elf_fn_entry_point_address(elf_handle,
							 fn_desc_addr);

  const std::pair<addr_symbol_map_type::const_iterator, bool>& result =
    entry_addr_symbol_map_.emplace(fn_entry_point_addr, symbol_sptr);

  const addr_symbol_map_type::const_iterator it = result.first;
  const bool was_inserted = result.second;
  if (!was_inserted
      && elf_helpers::address_is_in_opd_section(elf_handle, fn_desc_addr))
    {
      // Either
      //
      // 'symbol' must have been registered as an alias for
      // it->second->get_main_symbol()
      //
      // Or
      //
      // if the name of 'symbol' is foo, then the name of it2->second is
      // ".foo". That is, foo is the name of the symbol when it refers to the
      // function descriptor in the .opd section and ".foo" is an internal name
      // for the address of the entry point of foo.
      //
      // In the latter case, we just want to keep a reference to "foo" as .foo
      // is an internal name.

      const bool two_symbols_alias =
	it->second->get_main_symbol()->does_alias(*symbol_sptr);
      const bool symbol_is_foo_and_prev_symbol_is_dot_foo =
	(it->second->get_name() == std::string(".") + symbol_sptr->get_name());

      ABG_ASSERT(two_symbols_alias
		 || symbol_is_foo_and_prev_symbol_is_dot_foo);

      if (symbol_is_foo_and_prev_symbol_is_dot_foo)
	// Let's just keep a reference of the symbol that the user sees in the
	// source code (the one named foo). The symbol which name is prefixed
	// with a "dot" is an artificial one.
	entry_addr_symbol_map_[fn_entry_point_addr] = symbol_sptr;
    }
}

} // end namespace symtab_reader
} // end namespace abigail
