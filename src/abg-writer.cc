// -*- mode: C++ -*-
//
// Copyright (C) 2013-2019 Red Hat, Inc.
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

/// @file
///
/// This file contains the definitions of the entry points to
/// de-serialize an instance of @ref abigail::translation_unit to an
/// ABI Instrumentation file in libabigail native XML format.  This
/// native XML format is named "abixml".

#include "config.h"
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <stack>
#include <algorithm>
#include <tr1/unordered_map>

#include "abg-tools-utils.h"

#include "abg-internal.h"
// <headers defining libabigail's API go under here>
ABG_BEGIN_EXPORT_DECLARATIONS

#include "abg-config.h"
#include "abg-corpus.h"
#include "abg-diff-utils.h"
#include "abg-sptr-utils.h"

#if WITH_ZIP_ARCHIVE
#include "abg-libzip-utils.h"
#endif

#include "abg-writer.h"
#include "abg-libxml-utils.h"

ABG_END_EXPORT_DECLARATIONS
// </headers defining libabigail's API>

namespace abigail
{
using std::cerr;
using std::tr1::shared_ptr;
using std::tr1::dynamic_pointer_cast;
using std::tr1::static_pointer_cast;
using std::ofstream;
using std::ostream;
using std::ostringstream;
using std::list;
using std::vector;
using std::stack;
using std::tr1::unordered_map;
using abigail::sptr_utils::noop_deleter;

#if WITH_ZIP_ARCHIVE
using zip_utils::zip_sptr;
using zip_utils::zip_file_sptr;
using zip_utils::open_archive;
using zip_utils::open_file_in_archive;
#endif // WITH_ZIP_ARCHIVE

/// The namespace for the native XML file format writer.
///
/// It contains utilities to serialize ABI artifacts from the @ref ir
/// namespace into the native XML format.
namespace xml_writer
{

class id_manager
{
  const environment* m_env;
  mutable unsigned long long m_cur_id;

  unsigned long long
  get_new_id() const
  { return ++m_cur_id; }

public:
  id_manager(const environment* env)
    : m_env(env),
      m_cur_id(0) {}

  const environment*
  get_environment() const
  {return m_env;}

  /// Return a unique string representing a numerical id.
  interned_string
  get_id() const
  {
    ostringstream o;
    o << get_new_id();
    const environment* env = get_environment();
    ABG_ASSERT(env);
    return env->intern(o.str());
  }

  /// Return a unique string representing a numerical ID, prefixed by
  /// prefix.
  ///
  /// @param prefix the prefix of the returned unique id.
  interned_string
  get_id_with_prefix(const string& prefix) const
  {
    ostringstream o;
    o << prefix << get_new_id();
    const environment* env = get_environment();
    ABG_ASSERT(env);
    return env->intern(o.str());
  }
};

/// A hashing functor that should be as fast as possible.
struct type_hasher
{
  size_t
  operator()(const type_base* t) const
  {return hash_type_or_decl(t);}
}; // end struct type_hasher

/// A convenience typedef for a map that associates a pointer to type
/// to a string.  The pointer to type is hashed as fast as possible.
typedef unordered_map<type_base*,
		      interned_string,
		      type_hasher,
		      abigail::diff_utils::deep_ptr_eq_functor> type_ptr_map;

// A convenience typedef for a set of type_base*.
typedef unordered_set<const type_base*, type_hasher,
		      abigail::diff_utils::deep_ptr_eq_functor>
type_ptr_set_type;

typedef unordered_map<shared_ptr<function_tdecl>,
		      string,
		      function_tdecl::shared_ptr_hash> fn_tmpl_shared_ptr_map;

typedef unordered_map<shared_ptr<class_tdecl>,
		      string,
		      class_tdecl::shared_ptr_hash> class_tmpl_shared_ptr_map;

class write_context
{
  const environment*			m_env;
  id_manager				m_id_manager;
  config				m_config;
  ostream&				m_ostream;
  bool					m_annotate;
  bool					m_show_locs;
  mutable type_ptr_map			m_type_id_map;
  mutable type_ptr_set_type		m_emitted_type_set;
  type_ptr_set_type			m_emitted_decl_only_set;
  // A map of types that are referenced by emitted pointers,
  // references or typedefs
  type_ptr_map				m_referenced_types_map;
  fn_tmpl_shared_ptr_map		m_fn_tmpl_id_map;
  class_tmpl_shared_ptr_map		m_class_tmpl_id_map;
  string_elf_symbol_sptr_map_type	m_fun_symbol_map;
  string_elf_symbol_sptr_map_type	m_var_symbol_map;
  mutable unordered_map<interned_string,
			bool,
			hash_interned_string> m_emitted_decls_map;

  write_context();

public:

  /// Constructor.
  ///
  /// @param env the enviroment we are operating from.
  ///
  /// @param os the output stream to write to.
  write_context(const environment* env, ostream& os)
    : m_env(env),
      m_id_manager(env),
      m_ostream(os),
      m_annotate(false),
      m_show_locs(true)
  {}

  /// Getter of the environment we are operating from.
  ///
  /// @return the environment we are operating from.
  const environment*
  get_environment() const
  {return m_env;}

  const config&
  get_config() const
  {return m_config;}

  ostream&
  get_ostream()
  {return m_ostream;}

  /// Getter of the annotation option.
  ///
  /// @return true iff ABIXML annotations are turned on
  bool
  get_annotate()
  {return m_annotate;}

  /// Setter of the annotation option.
  ///
  /// @param f the new value of the flag.
  void
  set_annotate(bool f)
  {m_annotate = f;}

  /// Getter of the "show-locs" option.
  ///
  /// When this option is true then the XML writer emits location
  /// information for emitted ABI artifacts.
  ///
  /// @return the value of the "show-locs" option.
  bool
  get_show_locs() const
  {return m_show_locs;}

  /// Setter of the "show-locs" option.
  ///
  /// When this option is true then the XML writer emits location
  /// information for emitted ABI artifacts.
  ///
  /// @param f the new value of the "show-locs" option.
  void
  set_show_locs(bool f)
  {m_show_locs = f;}

  /// Getter of the @ref id_manager.
  ///
  /// @return the @ref id_manager used by the current instance of @ref
  /// write_context.
  const id_manager&
  get_id_manager() const
  {return m_id_manager;}

  id_manager&
  get_id_manager()
  {return m_id_manager;}

  /// @return true iff type has already been assigned an ID.
  bool
  type_has_existing_id(type_base_sptr type) const
  {return type_has_existing_id(type.get());}

  /// @return true iff type has already been assigned an ID.
  bool
  type_has_existing_id(type_base* type) const
  {
    type_base *c = type->get_naked_canonical_type();
    if (c == 0)
      c = const_cast<type_base*>(type);
    return (m_type_id_map.find(c) != m_type_id_map.end());
  }

  /// Associate a unique id to a given type.  For that, put the type
  /// in a hash table, hashing the type.  So if the type has no id
  /// associated to it, create a new one and return it.  Otherwise,
  /// return the existing id for that type.
  interned_string
  get_id_for_type(const type_base_sptr& t)
  {return get_id_for_type(t.get());}

  /// Associate a unique id to a given type.  For that, put the type
  /// in a hash table, hashing the type.  So if the type has no id
  /// associated to it, create a new one and return it.  Otherwise,
  /// return the existing id for that type.
  interned_string
  get_id_for_type(const type_base* t) const
  {
    type_base *c = t->get_naked_canonical_type();
    if (c == 0)
      c = const_cast<type_base*>(t);

    type_ptr_map::const_iterator it = m_type_id_map.find(c);
    if (it == m_type_id_map.end())
      {
	interned_string id =
	  get_id_manager().get_id_with_prefix("type-id-");
	m_type_id_map[c] = id;
	return id;
      }
    return it->second;
  }

  string
  get_id_for_fn_tmpl(const function_tdecl_sptr& f)
  {
    fn_tmpl_shared_ptr_map::const_iterator it = m_fn_tmpl_id_map.find(f);
    if (it == m_fn_tmpl_id_map.end())
      {
	string id = get_id_manager().get_id_with_prefix("fn-tmpl-id-");
	m_fn_tmpl_id_map[f] = id;
	return id;
      }
    return m_fn_tmpl_id_map[f];
  }

  string
  get_id_for_class_tmpl(const class_tdecl_sptr& c)
  {
    class_tmpl_shared_ptr_map::const_iterator it = m_class_tmpl_id_map.find(c);
    if (it == m_class_tmpl_id_map.end())
      {
	string id = get_id_manager().get_id_with_prefix("class-tmpl-id-");
	m_class_tmpl_id_map[c] = id;
	return id;
      }
    return m_class_tmpl_id_map[c];
  }

  void
  clear_type_id_map()
  {m_type_id_map.clear();}


  /// Getter of the map of types that were referenced by a pointer,
  /// reference or typedef.
  ///
  /// @return the map of types that were referenced.
  const type_ptr_map&
  get_referenced_types() const
  {return m_referenced_types_map;}

  /// Record a given type as being referenced by a pointer, a
  /// reference or a typedef type that is being emitted to the XML
  /// output.
  ///
  /// @param t a shared pointer to a type
  void
  record_type_as_referenced(const type_base_sptr& t)
  {m_referenced_types_map[t.get()] = interned_string();}

  /// Test if a given type has been referenced by a pointer, a
  /// reference or a typedef type that was emitted to the XML output.
  ///
  /// @param f a shared pointer to a type
  ///
  /// @return true if the type has been referenced, false
  /// otherwise.
  bool
  type_is_referenced(const type_base_sptr& t)
  {
    return m_referenced_types_map.find
      (t.get()) != m_referenced_types_map.end();
  }

  /// A comparison functor to compare pointers to @ref type_base.
  ///
  /// What is compared is the string representation of the pointed-to
  /// type.
  struct type_ptr_cmp
  {
    type_ptr_map *map;
    type_ptr_cmp(type_ptr_map *m)
      : map(m)
    {}

    /// The comparison operator of the functor.
    ///
    /// @param l the first type to consider.
    ///
    /// @param r the second type to consider.
    ///
    /// @return true if the string representation of type @p l is
    /// considered to be "less than" the string representation of the
    /// type @p r.
    ///
    /// But when the two string representations are equal (for
    /// instance, for typedefs that have the same string
    /// representation), this function compares the type-ids of the
    /// types.  This allows for a stable result.
    bool
    operator()(const type_base* l, const type_base* r) const
    {
      if (!l && r)
	return true;
      if (l && !r)
	return false;
      if (!l && !r)
	return false;

      string r1 = ir::get_pretty_representation(l),
	r2 = ir::get_pretty_representation(r);

      if (r1 == r2)
	{
	  type_ptr_map::const_iterator i =
	    map->find(const_cast<type_base*>(l));
	  if (i != map->end())
	    r1 = i->second;
	  i = map->find(const_cast<type_base*>(r));
	  if (i != map->end())
	    r2 = i->second;
	}

      return r1 < r2;
    }

    /// The comparison operator of the functor.
    ///
    /// @param l the first type to consider.
    ///
    /// @param r the second type to consider.
    ///
    /// @return true if the string representation of type @p l is
    /// considered to be "less than" the string representation of the
    /// type @p r.
    ///
    /// But when the two string representations are equal (for
    /// instance, for typedefs that have the same string
    /// representation), this function compares the type-ids of the
    /// types.  This allows for a stable result.
    bool
    operator()(const type_base_sptr& l, const type_base_sptr& r) const
    {return operator()(l.get(), r.get());}
  }; // end struct type_ptr_cmp

  /// Sort the content of a map of type pointers into a vector.
  ///
  /// The pointers are sorted by using their string representation as
  /// the key to sort, lexicographically.
  ///
  /// @param types the map to sort.
  ///
  /// @param sorted the resulted sorted vector.  It's set by this
  /// function with the result of the sorting.
  void
  sort_types(type_ptr_map& types,
	     vector<type_base*>& sorted)
  {
    string id;
    for (type_ptr_map::const_iterator i = types.begin();
	 i != types.end();
	 ++i)
	sorted.push_back(i->first);
    type_ptr_cmp comp(&m_type_id_map);
    sort(sorted.begin(), sorted.end(), comp);
  }

  /// Sort the content of a map of type pointers into a vector.
  ///
  /// The pointers are sorted by using their string representation as
  /// the key to sort, lexicographically.
  ///
  /// @param types the map to sort.
  ///
  /// @param sorted the resulted sorted vector.  It's set by this
  /// function with the result of the sorting.
  void
  sort_types(const istring_type_base_wptr_map_type& types,
	     vector<type_base_sptr> &sorted)
  {
    for (istring_type_base_wptr_map_type::const_iterator i = types.begin();
	 i != types.end();
	 ++i)
      sorted.push_back(type_base_sptr(i->second));
    type_ptr_cmp comp(&m_type_id_map);
    sort(sorted.begin(), sorted.end(), comp);
  }

  /// Sort the content of a vector of function types into a vector of
  /// types.
  ///
  /// The pointers are sorted by using their string representation as
  /// the key to sort, lexicographically.
  ///
  /// @param types the vector of function types to store.
  ///
  /// @param sorted the resulted sorted vector.  It's set by this
  /// function with the result of the sorting.
  void
  sort_types(const vector<function_type_sptr>& types,
	     vector<type_base_sptr> &sorted)
  {
    for (vector<function_type_sptr>::const_iterator i = types.begin();
	 i != types.end();
	 ++i)
      sorted.push_back(*i);
    type_ptr_cmp comp(&m_type_id_map);
    sort(sorted.begin(), sorted.end(), comp);
  }

  /// Flag a type as having been written out to the XML output.
  ///
  /// @param t the type to flag.
  void
  record_type_as_emitted(const type_base_sptr &t)
  {record_type_as_emitted(t.get());}

  /// Flag a type as having been written out to the XML output.
  ///
  /// @param t the type to flag.
  void
  record_type_as_emitted(const type_base *t)
  {
    type_base *c = t->get_naked_canonical_type();
    if (c == 0)
      c = const_cast<type_base*>(t);
    m_emitted_type_set.insert(c);
  }

  /// Test if a given type has been written out to the XML output.
  ///
  /// @param the type to test for.
  ///
  /// @return true if the type has already been emitted, false
  /// otherwise.
  bool
  type_is_emitted(const type_base *t)
  {
    type_base *c = t->get_naked_canonical_type();
    if (c == 0)
      c = const_cast<type_base*>(t);
    return m_emitted_type_set.find(c) != m_emitted_type_set.end();
  }

  /// Test if a given type has been written out to the XML output.
  ///
  /// @param the type to test for.
  ///
  /// @return true if the type has already been emitted, false
  /// otherwise.
  bool
  type_is_emitted(const type_base_sptr& t)
  {return type_is_emitted(t.get());}

  /// Test if the name of a given decl has been written out to the XML
  /// output.
  ///
  /// @param the decl to consider.
  ///
  /// @return true if the decl has already been emitted, false
  /// otherwise.
  bool
  decl_name_is_emitted(const interned_string& name) const
  {return m_emitted_decls_map.find(name) != m_emitted_decls_map.end();}

  /// Test if a given decl has been written out to the XML output.
  ///
  /// @param the decl to consider.
  ///
  /// @return true if the decl has already been emitted, false
  /// otherwise.
  bool
  decl_is_emitted(decl_base_sptr& decl) const
  {
    if (is_type(decl))
      return false;

    string repr = get_pretty_representation(decl, true);
    interned_string irepr = decl->get_environment()->intern(repr);
    bool is_emitted = decl_name_is_emitted(irepr);
    return is_emitted;
  }

  /// Record a declaration-only class as being emitted.
  ///
  /// For now, this function expects a declaration-only class,
  /// otherwise, it aborts.
  ///
  /// @param t the declaration-only class to report as emitted.
  void
  record_decl_only_type_as_emitted(type_base* t)
  {
    class_or_union* cl = is_class_or_union_type(t);
    ABG_ASSERT(cl && cl->get_is_declaration_only());
    m_emitted_decl_only_set.insert(t);
  }

  /// Record a declaration-only class as being emitted.
  ///
  /// For now, this function expects a declaration-only class,
  /// otherwise, it aborts.
  ///
  /// @param t the declaration-only class to report as emitted.
  void
  record_decl_only_type_as_emitted(const type_base_sptr& t)
  {record_decl_only_type_as_emitted(t.get());}

  /// Test if a declaration-only class has been emitted.
  ///
  /// @param t the declaration-only class to test for.
  ///
  /// @return true iff the declaration-only class @p t has been
  /// emitted.
  bool
  decl_only_type_is_emitted(type_base* t)
  {
    type_ptr_set_type::const_iterator i = m_emitted_decl_only_set.find(t);
    if (i == m_emitted_decl_only_set.end())
      return false;
    return true;
  }

  /// Test if a declaration-only class has been emitted.
  ///
  /// @param t the declaration-only class to test for.
  ///
  /// @return true iff the declaration-only class @p t has been
  /// emitted.
  bool
  decl_only_type_is_emitted(const type_base_sptr& t)
  {return decl_only_type_is_emitted(t.get());}

  /// Record a declaration as emitted in the abixml output.
  ///
  /// @param decl the decl to consider.
  void
  record_decl_as_emitted(const decl_base_sptr &decl)const
  {
    string repr = get_pretty_representation(decl, true);
    interned_string irepr = decl->get_environment()->intern(repr);
    m_emitted_decls_map[irepr] = true;
  }

  /// Clear the map that contains the IDs of the types that has been
  /// recorded as having been written out to the XML output.
  void
  clear_referenced_types_map()
  {m_referenced_types_map.clear();}

  const string_elf_symbol_sptr_map_type&
  get_fun_symbol_map() const
  {return m_fun_symbol_map;}

  string_elf_symbol_sptr_map_type&
  get_fun_symbol_map()
  {return m_fun_symbol_map;}

};//end write_context

static void write_location(const location&, write_context&);
static void write_location(const decl_base_sptr&, write_context&);
static bool write_visibility(const decl_base_sptr&, ostream&);
static bool write_binding(const decl_base_sptr&, ostream&);
static void write_array_size_and_alignment(const array_type_def_sptr,
					   ostream&);
static void write_size_and_alignment(const type_base_sptr, ostream&);
static void write_access(access_specifier, ostream&);
static void write_layout_offset(var_decl_sptr, ostream&);
static void write_layout_offset(class_decl::base_spec_sptr, ostream&);
static void write_cdtor_const_static(bool, bool, bool, bool, ostream&);
static void write_voffset(function_decl_sptr, ostream&);
static void write_elf_symbol_type(elf_symbol::type, ostream&);
static void write_elf_symbol_binding(elf_symbol::binding, ostream&);
static bool write_elf_symbol_aliases(const elf_symbol&, ostream&);
static bool write_elf_symbol_reference(const elf_symbol&, ostream&);
static bool write_elf_symbol_reference(const elf_symbol_sptr, ostream&);
static void write_class_or_union_is_declaration_only(const class_or_union_sptr&,
						     ostream&);
static void write_is_struct(const class_decl_sptr&, ostream&);
static void write_is_anonymous(const decl_base_sptr&, ostream&);
static void write_naming_typedef(const class_decl_sptr&, write_context&);
static bool write_decl(const decl_base_sptr&, write_context&, unsigned);
static void write_decl_in_scope(const decl_base_sptr&,
				write_context&, unsigned);
static bool write_type_decl(const type_decl_sptr&, write_context&, unsigned);
static bool write_namespace_decl(const namespace_decl_sptr&,
				 write_context&, unsigned);
static bool write_qualified_type_def(const qualified_type_def_sptr&,
				     write_context&, unsigned);
static bool write_pointer_type_def(const pointer_type_def_sptr&,
				   write_context&, unsigned);
static bool write_reference_type_def(const reference_type_def_sptr&,
				     write_context&, unsigned);
static bool write_array_type_def(const array_type_def_sptr&,
			         write_context&, unsigned);
static bool write_enum_type_decl(const enum_type_decl_sptr&,
				 write_context&, unsigned);
static bool write_typedef_decl(const typedef_decl_sptr&,
			       write_context&, unsigned);
static bool write_elf_symbol(const elf_symbol_sptr&,
			     write_context&, unsigned);
static bool write_elf_symbols_table(const elf_symbols&,
				    write_context&, unsigned);
static bool write_var_decl(const var_decl_sptr&,
			   write_context&, bool, unsigned);
static bool write_function_decl(const function_decl_sptr&,
				write_context&, bool, unsigned);
static bool write_function_type(const function_type_sptr&,
				write_context&, unsigned);
static bool write_member_type_opening_tag(const type_base_sptr&,
					  write_context&, unsigned);
static bool write_member_type(const type_base_sptr&,
			      write_context&, unsigned);
static bool write_class_decl_opening_tag(const class_decl_sptr&, const string&,
					 write_context&, unsigned, bool);
static bool write_class_decl(const class_decl_sptr&,
			     write_context&, unsigned);
static bool write_union_decl_opening_tag(const union_decl_sptr&, const string&,
					 write_context&, unsigned, bool);
static bool write_union_decl(const union_decl_sptr&, const string&,
			     write_context&, unsigned);
static bool write_union_decl(const union_decl_sptr&, write_context&, unsigned);
static bool write_type_tparameter
(const shared_ptr<type_tparameter>, write_context&, unsigned);
static bool write_non_type_tparameter
(const shared_ptr<non_type_tparameter>, write_context&, unsigned);
static bool write_template_tparameter
(const shared_ptr<template_tparameter>, write_context&, unsigned);
static bool write_type_composition
(const shared_ptr<type_composition>, write_context&, unsigned);
static bool write_template_parameter(const shared_ptr<template_parameter>,
				     write_context&, unsigned);
static void write_template_parameters(const shared_ptr<template_decl>,
				      write_context&, unsigned);
static bool write_function_tdecl
(const shared_ptr<function_tdecl>,
 write_context&, unsigned);
static bool write_class_tdecl
(const shared_ptr<class_tdecl>,
 write_context&, unsigned);
static void	do_indent(ostream&, unsigned);
static void	do_indent_to_level(write_context&, unsigned, unsigned);
static unsigned get_indent_to_level(write_context&, unsigned, unsigned);

/// Emit nb_whitespaces white spaces into the output stream.
void
do_indent(ostream& o, unsigned nb_whitespaces)
{
  for (unsigned i = 0; i < nb_whitespaces; ++i)
    o << ' ';
}

/// Indent initial_indent + level number of xml element indentation.
///
/// @param ctxt the context of the parsing.
///
/// @param initial_indent the initial number of white space to indent to.
///
/// @param level the number of indentation level to indent to.
static void
do_indent_to_level(write_context& ctxt,
		   unsigned initial_indent,
		   unsigned level)
{
  do_indent(ctxt.get_ostream(),
	    get_indent_to_level(ctxt, initial_indent, level));
}

/// Return the number of white space of indentation that
/// #do_indent_to_level would have used.
///
/// @param ctxt the context of the parsing.
///
/// @param initial_indent the initial number of white space to indent to.
///
/// @param level the number of indentation level to indent to.
static unsigned
get_indent_to_level(write_context& ctxt, unsigned initial_indent,
		    unsigned level)
{
    int nb_ws = initial_indent +
      level * ctxt.get_config().get_xml_element_indent();
    return nb_ws;
}

/// Annotate a declaration in form of an ABIXML comment.
///
/// This function is further specialized for declarations and types
/// with special requirements.
///
/// @tparam T shall be of type decl_base_sptr or a shared pointer to a
/// type derived from it, for the instantiation to be syntactically
/// correct.
///
/// @param decl_sptr the shared pointer to the declaration of type T.
///
/// @param ctxt the context of the parsing.
///
/// @param indent the amount of white space to indent to.
///
/// @return true iff decl is valid.
template <typename T>
static bool
annotate(const T&	decl,
	 write_context& ctxt,
	 unsigned	indent)
{
  if (!decl)
    return false;

  if (!ctxt.get_annotate())
    return true;

  ostream& o = ctxt.get_ostream();

  do_indent(o, indent);

  o << "<!-- "
    << xml::escape_xml_comment(decl->get_pretty_representation())
    << " -->\n";

  return true;
}

/// Annotate an elf symbol in form of an ABIXML comment, effectively
/// writing out its demangled form.
///
/// @param sym the symbol, whose name should be demangled.
///
/// @param ctxt the context of the parsing.
///
/// @param indent the amount of white space to indent to.
///
/// @return true iff decl is valid
template<>
bool
annotate(const elf_symbol_sptr& sym,
	 write_context&	ctxt,
	 unsigned		indent)
{
  if (!sym)
    return false;

  if (!ctxt.get_annotate())
    return true;

  ostream& o = ctxt.get_ostream();

  do_indent(o, indent);
  o << "<!-- "
    << xml::escape_xml_comment(abigail::ir::demangle_cplus_mangled_name(sym->get_name()))
    << " -->\n";

  return true;
}

/// Annotate a typedef declaration in form of an ABIXML comment.
///
/// @param typedef_decl the typedef to annotate.
///
/// @param ctxt the context of the parsing.
///
/// @param indent the amount of white space to indent to.
///
/// @return true iff decl is valid
template<>
bool
annotate(const typedef_decl_sptr&	typedef_decl,
	 write_context&		ctxt,
	 unsigned			indent)
{
  if (!typedef_decl)
    return false;

  if (!ctxt.get_annotate())
    return true;

  ostream& o = ctxt.get_ostream();

  do_indent(o, indent);

  o << "<!-- typedef "
    << get_type_name(typedef_decl->get_underlying_type())
    << " "
    << get_type_name(typedef_decl)
    << " -->\n";

  return true;
}

/// Annotate a function type in form of an ABIXML comment.
///
/// @param function_type the function type to annotate.
///
/// @param ctxt the context of the parsing.
///
/// @param indent the amount of white space to indent to.
///
/// @param skip_first_parm if true, do not serialize the first
/// parameter of the function decl.
//
/// @return true iff decl is valid
bool
annotate(const function_type_sptr&	function_type,
	 write_context&		ctxt,
	 unsigned			indent)
{
  if (!function_type)
    return false;

  if (!ctxt.get_annotate())
    return true;

  ostream& o = ctxt.get_ostream();

  do_indent(o, indent);
  o << "<!-- "
    << xml::escape_xml_comment(get_type_name(function_type->get_return_type()))
    << " (";

  vector<shared_ptr<function_decl::parameter> >::const_iterator pi =
    function_type->get_first_non_implicit_parm();

  for (; pi != function_type->get_parameters().end(); ++pi)
    {
      o << xml::escape_xml_comment((*pi)->get_type_name());
      // emit a comma after a param type, unless it's the last one
      if (distance(pi, function_type->get_parameters().end()) > 1)
	o << ", ";
    }
  o << ") -->\n";

  return true;
}

/// Annotate a function declaration in form of an ABIXML comment.
///
/// @param fn the function decl to annotate.
///
/// @param ctxt the context of the parsing.
///
/// @param indent the amount of white space to indent to.
///
/// @param skip_first_parm if true, do not serialize the first
/// parameter of the function decl.
//
/// @return true iff decl is valid
static bool
annotate(const function_decl_sptr&	fn,
	 write_context&		ctxt,
	 unsigned			indent)
{
  if (!fn)
    return false;

  if (!ctxt.get_annotate())
    return true;

  ostream& o = ctxt.get_ostream();

  do_indent(o, indent);
  o << "<!-- ";

  if (is_member_function(fn)
      && (get_member_function_is_ctor(fn) || get_member_function_is_dtor(fn)))
    ; // we don't emit return types for ctor or dtors
  else
    o << xml::escape_xml_comment(get_type_name(fn->get_return_type()))
      << " ";

  o << xml::escape_xml_comment(fn->get_qualified_name()) << "(";

  vector<function_decl::parameter_sptr>::const_iterator pi =
    fn->get_first_non_implicit_parm();

  for (; pi != fn->get_parameters().end(); ++pi)
    {
      o << xml::escape_xml_comment((*pi)->get_type_name());
      // emit a comma after a param type, unless it's the last one
      if (distance(pi, fn->get_parameters().end()) > 1)
	o << ", ";
    }
  o << ") -->\n";

  return true;
}

/// Annotate a function parameter in form of an ABIXML comment.
///
/// @param parm the function parameter to annotate.
///
/// @param ctxt the context of the parsing.
///
/// @param indent the amount of white space to indent to.
///
/// @return true iff decl is valid
template<>
bool
annotate(const function_decl::parameter_sptr&	parm,
	 write_context&			ctxt,
	 unsigned				indent)
{
  if (!parm)
    return false;

  if (!ctxt.get_annotate())
    return true;

  ostream &o = ctxt.get_ostream();

  do_indent(o, indent);

  o << "<!-- ";

  if (parm->get_variadic_marker())
    o << "variadic parameter";
  else
    {
      if (parm->get_artificial())
	{
	  if (parm->get_index() == 0)
	    o << "implicit ";
	  else
	    o << "artificial ";
	}
      o << "parameter of type '"
	<< xml::escape_xml_comment(get_pretty_representation(parm->get_type()));
    }

  o << "' -->\n" ;

  return true;
}

/// Write a location to the output stream.
///
/// If the location is empty, nothing is written.
///
/// @param loc the location to consider.
///
/// @param tu the translation unit the location belongs to.
///
/// @param ctxt the writer context to use.
static void
write_location(const location& loc, write_context& ctxt)
{
  if (!loc)
    return;

  if (!ctxt.get_show_locs())
    return;

  string filepath;
  unsigned line = 0, column = 0;

  loc.expand(filepath, line, column);

  ostream &o = ctxt.get_ostream();

  o << " filepath='" << xml::escape_xml_string(filepath) << "'"
    << " line='"     << line     << "'"
    << " column='"   << column   << "'";
}

/// Write the location of a decl to the output stream.
///
/// If the location is empty, nothing is written.
///
/// @param decl the decl to consider.
///
/// @param ctxt the @ref writer_context to use.
static void
write_location(const decl_base_sptr&	decl,
	       write_context&		ctxt)
{
  if (!decl)
    return;

  location loc = decl->get_location();
  if (!loc)
    return;

  write_location(loc, ctxt);
}

/// Serialize the visibility property of the current decl as the
/// 'visibility' attribute for the current xml element.
///
/// @param decl the instance of decl_base to consider.
///
/// @param o the output stream to serialize the property to.
///
/// @return true upon successful completion, false otherwise.
static bool
write_visibility(const shared_ptr<decl_base>&	decl, ostream& o)
{
  if (!decl)
    return false;

  decl_base::visibility v = decl->get_visibility();
  string str;

  switch (v)
    {
    case decl_base::VISIBILITY_NONE:
      return true;
    case decl_base::VISIBILITY_DEFAULT:
      str = "default";
      break;
    case decl_base::VISIBILITY_PROTECTED:
      str = "protected";
      break;
    case decl_base::VISIBILITY_HIDDEN:
      str = "hidden";
      break;
    case decl_base::VISIBILITY_INTERNAL:
	str = "internal";
	break;
    }

  if (str.empty())
    return false;

  o << " visibility='" << str << "'";

  return true;
}

/// Serialize the 'binding' property of the current decl.
///
/// @param decl the decl to consider.
///
/// @param o the output stream to serialize the property to.
static bool
write_binding(const shared_ptr<decl_base>& decl, ostream& o)
{
  if (!decl)
    return false;

  decl_base::binding bind = decl_base::BINDING_NONE;

  shared_ptr<var_decl> var =
    dynamic_pointer_cast<var_decl>(decl);
  if (var)
    bind = var->get_binding();
  else
    {
      shared_ptr<function_decl> fun =
	dynamic_pointer_cast<function_decl>(decl);
      if (fun)
	bind = fun->get_binding();
    }

  string str;
  switch (bind)
    {
    case decl_base::BINDING_NONE:
      break;
    case decl_base::BINDING_LOCAL:
      str = "local";
      break;
    case decl_base::BINDING_GLOBAL:
	str = "global";
      break;
    case decl_base::BINDING_WEAK:
      str = "weak";
      break;
    }

  if (!str.empty())
    o << " binding='" << str << "'";

  return true;
}

/// Serialize the size and alignment attributes of a given type.
///
/// @param decl the type to consider.
///
/// @param o the output stream to serialize to.
static void
write_size_and_alignment(const shared_ptr<type_base> decl, ostream& o)
{
  size_t size_in_bits = decl->get_size_in_bits();
  if (size_in_bits)
    o << " size-in-bits='" << size_in_bits << "'";

  size_t alignment_in_bits = decl->get_alignment_in_bits();
  if (alignment_in_bits)
    o << " alignment-in-bits='" << alignment_in_bits << "'";
}

/// Serialize the size and alignment attributes of a given type.
/// @param decl the type to consider.
///
/// @param o the output stream to serialize to.
static void
write_array_size_and_alignment(const shared_ptr<array_type_def> decl, ostream& o)
{
  if (decl->is_infinite())
    o << " size-in-bits='" << "infinite" << "'";
  else {
    size_t size_in_bits = decl->get_size_in_bits();
    if (size_in_bits)
      o << " size-in-bits='" << size_in_bits << "'";
  }

  size_t alignment_in_bits = decl->get_alignment_in_bits();
  if (alignment_in_bits)
    o << " alignment-in-bits='" << alignment_in_bits << "'";
}
/// Serialize the access specifier.
///
/// @param a the access specifier to serialize.
///
/// @param o the output stream to serialize it to.
static void
write_access(access_specifier a, ostream& o)
{
  string access_str = "private";

  switch (a)
    {
    case private_access:
      access_str = "private";
      break;

    case protected_access:
      access_str = "protected";
      break;

    case public_access:
      access_str = "public";
      break;

    default:
      break;
    }

  o << " access='" << access_str << "'";
}

/// Serialize the layout offset of a data member.
static void
write_layout_offset(var_decl_sptr member, ostream& o)
{
  if (!is_data_member(member))
    return;

  if (get_data_member_is_laid_out(member))
    o << " layout-offset-in-bits='"
      << get_data_member_offset(member)
      << "'";
}

/// Serialize the layout offset of a base class
static void
write_layout_offset(shared_ptr<class_decl::base_spec> base, ostream& o)
{
  if (!base)
    return;

  if (base->get_offset_in_bits() >= 0)
    o << " layout-offset-in-bits='" << base->get_offset_in_bits() << "'";
}

/// Serialize the access specifier of a class member.
///
/// @param member a pointer to the class member to consider.
///
/// @param o the ostream to serialize the member to.
static void
write_access(decl_base_sptr member, ostream& o)
{write_access(get_member_access_specifier(member), o);}

/// Write the voffset of a member function if it's non-zero
///
/// @param fn the member function to consider
///
/// @param o the output stream to write to
static void
write_voffset(function_decl_sptr fn, ostream&o)
{
  if (!fn)
    return;

  if (get_member_function_is_virtual(fn))
    {
      ssize_t voffset = get_member_function_vtable_offset(fn);
      o << " vtable-offset='" << voffset << "'";
    }
}

/// Serialize an elf_symbol::type into an XML node attribute named
/// 'type'.
///
/// @param t the elf_symbol::type to serialize.
///
/// @param o the output stream to serialize it to.
static void
write_elf_symbol_type(elf_symbol::type t, ostream& o)
{
  string repr;

  switch (t)
    {
    case elf_symbol::NOTYPE_TYPE:
      repr = "no-type";
      break;
    case elf_symbol::OBJECT_TYPE:
      repr = "object-type";
      break;
    case elf_symbol::FUNC_TYPE:
      repr = "func-type";
      break;
    case elf_symbol::SECTION_TYPE:
      repr = "section-type";
      break;
    case elf_symbol::FILE_TYPE:
      repr = "file-type";
      break;
    case elf_symbol::COMMON_TYPE:
      repr = "common-type";
      break;
    case elf_symbol::TLS_TYPE:
      repr = "tls-type";
      break;
    case elf_symbol::GNU_IFUNC_TYPE:
      repr = "gnu-ifunc-type";
      break;
    default:
      repr = "no-type";
      break;
    }

  o << " type='" << repr << "'";
}

/// Serialize an elf_symbol::binding into an XML element attribute of
/// name 'binding'.
///
/// @param b the elf_symbol::binding to serialize.
///
/// @param o the output stream to serialize the binding to.
static void
write_elf_symbol_binding(elf_symbol::binding b, ostream& o)
{
  string repr;

  switch (b)
    {
    case elf_symbol::LOCAL_BINDING:
      repr = "local-binding";
      break;
    case elf_symbol::GLOBAL_BINDING:
      repr = "global-binding";
      break;
    case elf_symbol::WEAK_BINDING:
      repr = "weak-binding";
      break;
    case elf_symbol::GNU_UNIQUE_BINDING:
      repr = "gnu-unique-binding";
      break;
    default:
      repr = "no-binding";
      break;
    }

  o << " binding='" << repr << "'";
}

/// Serialize an elf_symbol::binding into an XML element attribute of
/// name 'binding'.
///
/// @param b the elf_symbol::binding to serialize.
///
/// @param o the output stream to serialize the binding to.
static void
write_elf_symbol_visibility(elf_symbol::visibility v, ostream& o)
{
  string repr;

  switch (v)
    {
    case elf_symbol::DEFAULT_VISIBILITY:
      repr = "default-visibility";
      break;
    case elf_symbol::PROTECTED_VISIBILITY:
      repr = "protected-visibility";
      break;
    case elf_symbol::HIDDEN_VISIBILITY:
      repr = "hidden-visibility";
      break;
    case elf_symbol::INTERNAL_VISIBILITY:
      repr = "internal-visibility";
      break;
    default:
      repr = "default-visibility";
      break;
    }

  o << " visibility='" << repr << "'";
}

/// Write alias attributes for the aliases of a given symbol.
///
/// @param sym the symbol to write the attributes for.
///
/// @param o the output stream to write the attributes to.
///
/// @return true upon successful completion.
static bool
write_elf_symbol_aliases(const elf_symbol& sym, ostream& o)
{
  if (!sym.is_main_symbol() || !sym.has_aliases())
    return false;

  bool emitted = false;
  o << " alias='";
  for (elf_symbol_sptr s = sym.get_next_alias();
       !s->is_main_symbol();
       s = s->get_next_alias())
    {
      if (s->get_next_alias()->is_main_symbol())
	o << s->get_id_string() << "'";
      else
	o << s->get_id_string() << ",";

      emitted = true;
    }

  return emitted;
}

/// Write an XML attribute for the reference to a symbol for the
/// current decl.
///
/// @param sym the symbol to consider.
///
/// @param o the output stream to write the attribute to.
///
/// @return true upon successful completion.
static bool
write_elf_symbol_reference(const elf_symbol& sym, ostream& o)
{
  o << " elf-symbol-id='" << sym.get_id_string() << "'";
  return true;
}

/// Write an XML attribute for the reference to a symbol for the
/// current decl.
///
/// @param sym the symbol to consider.
///
/// @param o the output stream to write the attribute to.
///
/// @return true upon successful completion.
static bool
write_elf_symbol_reference(const elf_symbol_sptr sym, ostream& o)
{
  if (!sym)
    return false;

  return write_elf_symbol_reference(*sym, o);
}

/// Serialize the attributes "constructor", "destructor" or "static"
/// if they have true value.
///
/// @param is_ctor if set to true, the "constructor='true'" string is
/// emitted.
///
/// @param is_dtor if set to true the "destructor='true' string is
/// emitted.
///
/// @param is_static if set to true the "static='true'" string is
/// emitted.
///
/// @param o the output stream to use for the serialization.
static void
write_cdtor_const_static(bool is_ctor,
			 bool is_dtor,
			 bool is_const,
			 bool is_static,
			 ostream& o)
{
  if (is_static)
    o << " static='yes'";
  if (is_ctor)
    o << " constructor='yes'";
  else if (is_dtor)
    o << " destructor='yes'";
  if (is_const)
    o << " const='yes'";
}

/// Serialize the attribute "is-declaration-only", if the class or
/// union has its 'is_declaration_only property set.
///
/// @param t the pointer to instance of @ref class_or_union to
/// consider.
///
/// @param o the output stream to serialize to.
static void
write_class_or_union_is_declaration_only(const class_or_union_sptr& t,
					 ostream& o)
{
  if (t->get_is_declaration_only())
    o << " is-declaration-only='yes'";
}

/// Serialize the attribute "is-struct", if the current instance of
/// class_decl is a struct.
///
/// @param klass a pointer to the instance of class_decl to consider.
///
/// @param o the output stream to serialize to.
static void
write_is_struct(const class_decl_sptr& klass, ostream& o)
{
  if (klass->is_struct())
    o << " is-struct='yes'";
}

/// Serialize the attribute "is-anonymous", if the current instance of
/// decl is anonymous
///
/// @param dcl a pointer to the instance of @ref decl_base to consider.
///
/// @param o the output stream to serialize to.
static void
write_is_anonymous(const decl_base_sptr& decl, ostream& o)
{
  if (decl->get_is_anonymous())
    o << " is-anonymous='yes'";
}

/// Serialize the "naming-typedef-id" attribute, if the current
/// instance of @ref class_decl has a naming typedef.
///
/// @param klass the @ref class_decl to consider.
///
/// @param ctxt the write context to use.
static void
write_naming_typedef(const class_decl_sptr& klass, write_context& ctxt)
{
  if (!klass)
    return;

  ostream &o = ctxt.get_ostream();

  if (typedef_decl_sptr typedef_type = klass->get_naming_typedef())
    {
      string id = ctxt.get_id_for_type(typedef_type);
      o << " naming-typedef-id='" << id << "'";
    }
}

/// Serialize a pointer to an of decl_base into an output stream.
///
/// @param decl the pointer to decl_base to serialize
///
/// @param ctxt the context of the serialization.  It contains e.g, the
/// output stream to serialize to.
///
/// @param indent how many indentation spaces to use during the
/// serialization.
///
/// @return true upon successful completion, false otherwise.
static bool
write_decl(const decl_base_sptr& decl, write_context& ctxt, unsigned indent)
{
  if (write_type_decl(dynamic_pointer_cast<type_decl> (decl),
		      ctxt, indent)
      || write_namespace_decl(dynamic_pointer_cast<namespace_decl>(decl),
			      ctxt, indent)
      || write_qualified_type_def (dynamic_pointer_cast<qualified_type_def>
				   (decl),
				   ctxt, indent)
      || write_pointer_type_def(dynamic_pointer_cast<pointer_type_def>(decl),
				ctxt, indent)
      || write_reference_type_def(dynamic_pointer_cast
				  <reference_type_def>(decl), ctxt, indent)
      || write_array_type_def(dynamic_pointer_cast
			      <array_type_def>(decl), ctxt, indent)
      || write_enum_type_decl(dynamic_pointer_cast<enum_type_decl>(decl),
			      ctxt, indent)
      || write_typedef_decl(dynamic_pointer_cast<typedef_decl>(decl),
			    ctxt, indent)
      || write_var_decl(dynamic_pointer_cast<var_decl>(decl), ctxt,
			/*write_linkage_name=*/true, indent)
      || write_function_decl(dynamic_pointer_cast<method_decl>
			     (decl), ctxt, /*skip_first_parameter=*/true,
			     indent)
      || write_function_decl(dynamic_pointer_cast<function_decl>(decl),
			     ctxt, /*skip_first_parameter=*/false, indent)
      || write_class_decl(is_class_type(decl), ctxt, indent)
      || write_union_decl(is_union_type(decl), ctxt, indent)
      || (write_function_tdecl
	  (dynamic_pointer_cast<function_tdecl>(decl), ctxt, indent))
      || (write_class_tdecl
	  (dynamic_pointer_cast<class_tdecl>(decl), ctxt, indent)))
    return true;

  return false;
}

/// Emit a declaration, along with its scope.
///
/// This function is called at the end of emitting a translation unit,
/// to emit type declarations that were referenced by types that were
/// emitted in the TU already, but that were not emitted themselves.
///
/// @param decl the decl to emit.
///
/// @param ctxt the write context to use.
///
/// @param initial_indent the number of indentation spaces to use.
static void
write_decl_in_scope(const decl_base_sptr&	decl,
		    write_context&		ctxt,
		    unsigned			initial_indent)
{
  type_base_sptr type = is_type(decl);
  ABG_ASSERT(type);

  if (ctxt.type_is_emitted(type))
    return;

  list<scope_decl*> scopes;
  for (scope_decl* s = decl->get_scope();
       s && !is_global_scope(s);
       s = s->get_scope())
    scopes.push_front(s);

  ostream& o = ctxt.get_ostream();
  const config& c = ctxt.get_config();
  stack<string> closing_tags;
  stack<unsigned> closing_indents;
  unsigned indent = initial_indent;
  bool wrote_context = false;
  for (list<scope_decl*>::const_iterator i = scopes.begin();
       i != scopes.end();
       ++i)
    {
      ABG_ASSERT(!is_global_scope(*i));

      if (i != scopes.begin())
	o << "\n";

      // A type scope is either a namespace ...
      if (namespace_decl* n = is_namespace(*i))
	{
	  do_indent(o, indent);
	  o << "<namespace-decl name='"
	    << xml::escape_xml_string(n->get_name())
	    << "'>";
	  closing_tags.push("</namespace-decl>");
	  closing_indents.push(indent);
	}
      // ... or a class.
      else if (class_decl* c = is_class_type(*i))
	{
	  class_decl_sptr class_type(c, noop_deleter());
	  write_class_decl_opening_tag(class_type, "", ctxt, indent,
				       /*prepare_to_handle_members=*/false);
	  closing_tags.push("</class-decl>");
	  closing_indents.push(indent);

	  unsigned nb_ws = get_indent_to_level(ctxt, indent, 1);
	  write_member_type_opening_tag(type, ctxt, nb_ws);
	  indent = nb_ws;
	  closing_tags.push("</member-type>");
	  closing_indents.push(nb_ws);
	}
      else if (union_decl *u = is_union_type(*i))
	{
	  union_decl_sptr union_type(u, noop_deleter());
	  write_union_decl_opening_tag(union_type, "", ctxt, indent,
				       /*prepare_to_handle_members=*/false);
	  closing_tags.push("</union-decl>");
	  closing_indents.push(indent);

	  unsigned nb_ws = get_indent_to_level(ctxt, indent, 1);
	  write_member_type_opening_tag(type, ctxt, nb_ws);
	  indent = nb_ws;
	  closing_tags.push("</member-type>");
	  closing_indents.push(nb_ws);
	}
      else
	// We should never reach this point.
	abort();
      indent += c.get_xml_element_indent();
      wrote_context = true;
    }

  if (wrote_context)
    o << "\n";

  write_decl(decl, ctxt, indent);

  while (!closing_tags.empty())
    {
      o << "\n";
      do_indent(o, closing_indents.top());
      o << closing_tags.top();
      closing_tags.pop();
      closing_indents.pop();
    }
}

/// Create a @ref write_context object that can be used to emit abixml
/// files.
///
/// @param env the environment for the @ref write_context object to use.
///
/// @param default_output_stream the default output stream to use.
///
/// @return the new @ref write_context object.
write_context_sptr
create_write_context(const environment *env,
		     ostream& default_output_stream)
{
  write_context_sptr ctxt(new write_context(env, default_output_stream));
  return ctxt;
}

/// Set the "show-locs" flag.
///
/// When this flag is set then the XML writer emits location (///
/// information (file name, line and column) for the ABI artifacts
/// that it emits.
///
/// @param ctxt the @ref write_context to set the option for.
///
/// @param flag the new value of the option.
void
set_show_locs(write_context& ctxt, bool flag)
{ctxt.set_show_locs(flag);}

/// Set the 'annotate' flag.
///
/// When this flag is set then the XML writer annotates ABI artifacts
/// with a human readable description.
///
/// @param ctxt the context to set this flag on to.
///
/// @param flag the new value of the 'annotate' flag.
void
set_annotate(write_context& ctxt, bool flag)
{ctxt.set_annotate(flag);}

/// Serialize a translation unit to an output stream.
///
/// @param ctxt the context of the serialization.  It contains e.g,
/// the output stream to serialize to.
///
/// @param tu the translation unit to serialize.
///
/// @param indent how many indentation spaces to use during the
/// serialization.
///
/// @return true upon successful completion, false otherwise.
bool
write_translation_unit(write_context&	       ctxt,
		       const translation_unit& tu,
		       const unsigned	       indent)
{
  ostream& o = ctxt.get_ostream();
  const config& c = ctxt.get_config();

  do_indent(o, indent);

  o << "<abi-instr version='"
    << c.get_format_major_version_number()
    << "." << c.get_format_minor_version_number()
    << "'";

  if (tu.get_address_size() != 0)
    o << " address-size='" << static_cast<int>(tu.get_address_size()) << "'";

  if (!tu.get_path().empty())
    o << " path='" << xml::escape_xml_string(tu.get_path()) << "'";

  if (!tu.get_compilation_dir_path().empty())
    o << " comp-dir-path='"
      << xml::escape_xml_string(tu.get_compilation_dir_path()) << "'";

  if (tu.get_language() != translation_unit::LANG_UNKNOWN)
    o << " language='"
      << translation_unit_language_to_string(tu.get_language())
      <<"'";

  if (tu.is_empty())
    {
      o << "/>";
      return true;
    }

  o << ">";

  typedef scope_decl::declarations declarations;
  typedef declarations::const_iterator const_iterator;
  const declarations& d = tu.get_global_scope()->get_member_decls();

  for (const_iterator i = d.begin(); i != d.end(); ++i)
    {
      if (type_base_sptr t = is_type(*i))
	if (ctxt.type_is_emitted(t))
	  // This type has already been written out to the current
	  // translation unit, so do not emit it again.
	  continue;

      if (decl_base_sptr d = is_decl(*i))
	if (ctxt.decl_is_emitted(d))
	  continue;

      o << "\n";
      write_decl(*i, ctxt, indent + c.get_xml_element_indent());
    }

  // Now let's handle types that were referenced, but not yet
  // emitted.  We must emit those, along with their scope.

  // So this map of type -> string is to contain the referenced types
  // we need to emit.
  type_ptr_map referenced_types_to_emit;

  for (type_ptr_map::const_iterator i = ctxt.get_referenced_types().begin();
       i != ctxt.get_referenced_types().end();
       ++i)
    {
      type_base_sptr type(i->first, noop_deleter());
      if (!ctxt.type_is_emitted(type)
	  && !ctxt.decl_only_type_is_emitted(type))
	// A referenced type that was not emitted at all must be
	// emitted now.
	referenced_types_to_emit[type.get()] = interned_string();
    }

  // Ok, now let's emit the referenced type for good.
  while (!referenced_types_to_emit.empty())
    {
      // But first, we need to sort them, otherwise, emitting the ABI
      // (in xml) of the same binary twice will yield different
      // results, because we'd be walking an *unordered* hash table.
      vector<type_base*> sorted_referenced_types;
      ctxt.sort_types(referenced_types_to_emit,
		      sorted_referenced_types);

      // Now, emit the referenced decls in a sorted order.
      for (vector<type_base*>::const_iterator i =
	     sorted_referenced_types.begin();
	   i != sorted_referenced_types.end();
	   ++i)
	{
	  // We handle types which have declarations *and* function
	  // types here.
	  type_base_sptr t(*i, noop_deleter());
	  if (!ctxt.type_is_emitted(t))
	    {
	      if (decl_base* d = get_type_declaration(*i))
		{
		  decl_base_sptr decl(d, noop_deleter());
		  o << "\n";
		  write_decl_in_scope(decl, ctxt,
				      indent + c.get_xml_element_indent());
		}
	      else if (function_type_sptr fn_type = is_function_type(t))
		{
		  o << "\n";
		  write_function_type(fn_type, ctxt,
				      indent + c.get_xml_element_indent());
		}
	      else
		ABG_ASSERT_NOT_REACHED;
	    }
	}

      // So all referenced types that we wanted to emit were emitted.
      referenced_types_to_emit.clear();

      // But then, while emitting those referenced type, other types
      // might have been referenced by those referenced types
      // themselves!  So let's look at the map of referenced type that
      // is maintained for the entire ABI corpus and see if there are
      // still some referenced types in there that are not emitted
      // yet.  If yes, then we'll emit those again.
      for (type_ptr_map::const_iterator i =
	     ctxt.get_referenced_types().begin();
	   i != ctxt.get_referenced_types().end();
	   ++i)
	{
	  type_base_sptr type(i->first, noop_deleter());
	  if (!ctxt.type_is_emitted(type)
	      && !ctxt.decl_only_type_is_emitted(type))
	    referenced_types_to_emit[type.get()] = interned_string();
	}
    }

  // Now handle all function types that were not only referenced by
  // emitted types.
  const vector<function_type_sptr>& t = tu.get_live_fn_types();
  vector<type_base_sptr> sorted_types;
  ctxt.sort_types(t, sorted_types);

  for (vector<type_base_sptr>::const_iterator i = sorted_types.begin();
       i != sorted_types.end();
       ++i)
    {
      function_type_sptr fn_type = is_function_type(*i);

      if (!ctxt.type_is_referenced(fn_type) || ctxt.type_is_emitted(fn_type))
	// This function type is either not referenced by any emitted
	// pointer or reference type, or has already been emitted, so skip it.
	continue;

      ABG_ASSERT(fn_type);
      o << "\n";
      write_function_type(fn_type, ctxt, indent + c.get_xml_element_indent());
    }

  o << "\n";
  do_indent(o, indent);
  o << "</abi-instr>\n";

  return true;
}

/// Serialize a translation unit to an output stream.
///
/// @param tu the translation unit to serialize.
///
/// @param indent how many indentation spaces to use during the
/// serialization.
///
/// @param out the output stream to serialize the translation unit to.
///
/// @param annotate whether to annotate the output with debug information
///
/// @deprecated use write_translation_unit(ctct, tu, indent)
///
/// @return true upon successful completion, false otherwise.
bool ABG_DEPRECATED
write_translation_unit(const translation_unit& tu,
		       unsigned		       indent,
		       std::ostream&	       out,
		       const bool	       annotate)
{
  write_context ctxt(tu.get_environment(), out);
  set_annotate(ctxt, annotate);
  return write_translation_unit(ctxt, tu, indent);
}

/// Serialize a translation unit to a file.
///
/// @param tu the translation unit to serialize.
///
/// @param indent how many indentation spaces to use during the
/// serialization.
///
/// @param path the file to serialize the translation unit to.
///
/// @param annotate whether to annotate the output with debug information
///
/// @deprecated use write_translation_unit(ctct, tu, indent)
///
/// @return true upon successful completion, false otherwise.
bool ABG_DEPRECATED
write_translation_unit(const translation_unit& tu,
		       unsigned		       indent,
		       const string&	       path,
		       const bool	       annotate)
{
  bool result = true;

  try
    {
      ofstream of(path.c_str(), std::ios_base::trunc);
      if (!of.is_open())
	{
	  cerr << "failed to access " << path << "\n";
	  return false;
	}

      write_context ctxt(tu.get_environment(), of);
      set_annotate(ctxt, annotate);
      if (!write_translation_unit(ctxt, tu, indent))
	{
	  cerr << "failed to access " << path << "\n";
	  result = false;
	}

      of.close();
    }
  catch(...)
    {
      cerr << "failed to write to " << path << "\n";
      result = false;
    }

  return result;
}


/// Serialize a pointer to an instance of basic type declaration, into
/// an output stream.
///
/// @param d the basic type declaration to serialize.
///
/// @param ctxt the context of the serialization.  It contains e.g, the
/// output stream to serialize to.
///
/// @param indent how many indentation spaces to use during the
/// serialization.
///
/// @return true upon successful completion, false otherwise.
static bool
write_type_decl(const type_decl_sptr& d, write_context& ctxt, unsigned indent)
{
  if (!d)
    return false;

  ostream& o = ctxt.get_ostream();

  annotate(d, ctxt, indent);

  do_indent(o, indent);

  o << "<type-decl name='" << xml::escape_xml_string(d->get_name()) << "'";

  write_is_anonymous(d, o);

  write_size_and_alignment(d, o);

  write_location(d, ctxt);

  o << " id='" << ctxt.get_id_for_type(d) << "'" <<  "/>";

  ctxt.record_type_as_emitted(d);

  return true;
}

/// Serialize a namespace declaration int an output stream.
///
/// @param decl the namespace declaration to serialize.
///
/// @param ctxt the context of the serialization.  It contains e.g, the
/// output stream to serialize to.
///
/// @param indent how many indentation spaces to use during the
/// serialization.
///
/// @return true upon successful completion, false otherwise.
static bool
write_namespace_decl(const namespace_decl_sptr& decl,
		     write_context& ctxt, unsigned indent)
{
  if (!decl || decl->is_empty_or_has_empty_sub_namespaces())
    return false;

  ostream& o = ctxt.get_ostream();
  const config &c = ctxt.get_config();

  annotate(decl, ctxt, indent);

  do_indent(o, indent);

  o << "<namespace-decl name='"
    << xml::escape_xml_string(decl->get_name())
    << "'>";

  typedef scope_decl::declarations		declarations;
  typedef declarations::const_iterator const_iterator;
  const declarations& d = decl->get_member_decls();

  for (const_iterator i = d.begin(); i != d.end(); ++i)
    {
      if (type_base_sptr t = is_type(*i))
	if (ctxt.type_is_emitted(t))
	  // This type has already been emitted to the current
	  // translation unit so do not emit it again.
	  continue;
      o << "\n";
      write_decl(*i, ctxt, indent + c.get_xml_element_indent());
    }

  o << "\n";
  do_indent(o, indent);
  o << "</namespace-decl>";

  return true;
}

/// Serialize a qualified type declaration to an output stream.
///
/// @param decl the qualfied type declaration to write.
///
/// @param id the type id identitifier to use in the serialized
/// output.  If this is empty, the function will compute an
/// appropriate one.  This is useful when this function is called to
/// serialize the underlying type of a member type; in that case, the
/// caller has already computed the id of the *member type*, and that
/// id is the one to be written as the value of the 'id' attribute of
/// the XML element of the underlying type.
///
/// @param ctxt the write context.
///
/// @param indent the number of space to indent to during the
/// serialization.
///
/// @return true upon successful completion, false otherwise.
static bool
write_qualified_type_def(const qualified_type_def_sptr&	decl,
			 const string&				id,
			 write_context&			ctxt,
			 unsigned				indent)
{
  if (!decl)
    return false;

  ostream& o = ctxt.get_ostream();


  type_base_sptr underlying_type = decl->get_underlying_type();

  annotate(decl, ctxt, indent);

  do_indent(o, indent);
  o << "<qualified-type-def type-id='"
    << ctxt.get_id_for_type(underlying_type)
    << "'";

  ctxt.record_type_as_referenced(underlying_type);

  if (decl->get_cv_quals() & qualified_type_def::CV_CONST)
    o << " const='yes'";
  if (decl->get_cv_quals() & qualified_type_def::CV_VOLATILE)
    o << " volatile='yes'";
  if (decl->get_cv_quals() & qualified_type_def::CV_RESTRICT)
    o << " restrict='yes'";

  write_location(static_pointer_cast<decl_base>(decl), ctxt);

  string i = id;
  if (i.empty())
    i = ctxt.get_id_for_type(decl);

  o<< " id='" << i << "'/>";

  ctxt.record_type_as_emitted(decl);

  return true;
}

/// Serialize a qualified type declaration to an output stream.
///
/// @param decl the qualfied type declaration to write.
///
/// @param ctxt the write context.
///
/// @param indent the number of space to indent to during the
/// serialization.
///
/// @return true upon successful completion, false otherwise.
static bool
write_qualified_type_def(const qualified_type_def_sptr&	decl,
			 write_context&			ctxt,
			 unsigned				indent)
{return write_qualified_type_def(decl, "", ctxt, indent);}

/// Serialize a pointer to an instance of pointer_type_def.
///
/// @param decl the pointer_type_def to serialize.
///
/// @param id the type id identitifier to use in the serialized
/// output.  If this is empty, the function will compute an
/// appropriate one.  This is useful when this function is called to
/// serialize the underlying type of a member type; in that case, the
/// caller has already computed the id of the *member type*, and that
/// id is the one to be written as the value of the 'id' attribute of
/// the XML element of the underlying type.
///
/// @param ctxt the context of the serialization.
///
/// @param indent the number of indentation white spaces to use.
///
/// @return true upon succesful completion, false otherwise.
static bool
write_pointer_type_def(const pointer_type_def_sptr&	decl,
		       const string&			id,
		       write_context&			ctxt,
		       unsigned			indent)
{
  if (!decl)
    return false;

  ostream& o = ctxt.get_ostream();


  type_base_sptr pointed_to_type = decl->get_pointed_to_type();

  annotate(decl->get_canonical_type(), ctxt, indent);

  do_indent(o, indent);
  o << "<pointer-type-def type-id='"
    << ctxt.get_id_for_type(pointed_to_type)
    << "'";

  ctxt.record_type_as_referenced(pointed_to_type);

  write_size_and_alignment(decl, o);

  string i = id;
  if (i.empty())
    i = ctxt.get_id_for_type(decl);

  o << " id='" << i << "'";

  write_location(static_pointer_cast<decl_base>(decl), ctxt);
  o << "/>";

  ctxt.record_type_as_emitted(decl);

  return true;
}

/// Serialize a pointer to an instance of pointer_type_def.
///
/// @param decl the pointer_type_def to serialize.
///
/// @param ctxt the context of the serialization.
///
/// @param indent the number of indentation white spaces to use.
///
/// @return true upon succesful completion, false otherwise.
static bool
write_pointer_type_def(const pointer_type_def_sptr&	decl,
		       write_context&			ctxt,
		       unsigned			indent)
{return write_pointer_type_def(decl, "", ctxt, indent);}

/// Serialize a pointer to an instance of reference_type_def.
///
/// @param decl the reference_type_def to serialize.
///
/// @param id the type id identitifier to use in the serialized
/// output.  If this is empty, the function will compute an
/// appropriate one.  This is useful when this function is called to
/// serialize the underlying type of a member type; in that case, the
/// caller has already computed the id of the *member type*, and that
/// id is the one to be written as the value of the 'id' attribute of
/// the XML element of the underlying type.
///
/// @param ctxt the context of the serialization.
///
/// @param indent the number of indentation white spaces to use.
///
/// @return true upon succesful completion, false otherwise.
static bool
write_reference_type_def(const reference_type_def_sptr&	decl,
			 const string&				id,
			 write_context&			ctxt,
			 unsigned				indent)
{
  if (!decl)
    return false;

  annotate(decl->get_canonical_type(), ctxt, indent);

  ostream& o = ctxt.get_ostream();

  do_indent(o, indent);

  o << "<reference-type-def kind='";
  if (decl->is_lvalue())
    o << "lvalue";
  else
    o << "rvalue";
  o << "'";

  type_base_sptr pointed_to_type = decl->get_pointed_to_type();
  o << " type-id='" << ctxt.get_id_for_type(pointed_to_type) << "'";

  ctxt.record_type_as_referenced(pointed_to_type);

  if (function_type_sptr f = is_function_type(decl->get_pointed_to_type()))
    ctxt.record_type_as_referenced(f);

  write_size_and_alignment(decl, o);

  string i = id;
  if (i.empty())
    i = ctxt.get_id_for_type(decl);
  o << " id='" << i << "'";

  write_location(static_pointer_cast<decl_base>(decl), ctxt);

  o << "/>";

  ctxt.record_type_as_emitted(decl);

  return true;
}

/// Serialize a pointer to an instance of reference_type_def.
///
/// @param decl the reference_type_def to serialize.
///
/// @param ctxt the context of the serialization.
///
/// @param indent the number of indentation white spaces to use.
///
/// @return true upon succesful completion, false otherwise.
static bool
write_reference_type_def(const reference_type_def_sptr&	decl,
			 write_context&			ctxt,
			 unsigned				indent)
{return write_reference_type_def(decl, "", ctxt, indent);}

/// Serialize an instance of @ref array_type_def::subrange_type.
///
/// @param decl the array_type_def::subrange_type to serialize.
///
/// @param ctxt the context of the serialization.
///
/// @param indent the number of indentation white spaces to use.
///
/// return true upon successful completion, false otherwise.
static bool
write_array_subrange_type(const array_type_def::subrange_sptr&	decl,
			  write_context&			ctxt,
			  unsigned				indent)
{
  if (!decl)
    return false;

  annotate(decl, ctxt, indent);

  ostream& o = ctxt.get_ostream();

  do_indent(o, indent);

  o << "<subrange";

  if (!decl->get_name().empty())
    o << " name='" << decl->get_name() << "'";

  o << " length='";
  if (decl->is_infinite())
    o << "infinite";
  else
    o << decl->get_length();

  o << "'";

  type_base_sptr underlying_type = decl->get_underlying_type();
  if (underlying_type)
    {
      o << " type-id='"
	<< ctxt.get_id_for_type(underlying_type)
	<< "'";
      ctxt.record_type_as_referenced(underlying_type);
    }

  o << " id='" << ctxt.get_id_for_type(decl) << "'";

  write_location(decl->get_location(), ctxt);

  o << "/>\n";

  return true;
}

/// Serialize a pointer to an instance of array_type_def.
///
/// @param decl the array_type_def to serialize.
///
/// @param id the type id identitifier to use in the serialized
/// output.  If this is empty, the function will compute an
/// appropriate one.  This is useful when this function is called to
/// serialize the underlying type of a member type; in that case, the
/// caller has already computed the id of the *member type*, and that
/// id is the one to be written as the value of the 'id' attribute of
/// the XML element of the underlying type.
///
/// @param ctxt the context of the serialization.
///
/// @param indent the number of indentation white spaces to use.
///
/// @return true upon succesful completion, false otherwise.
static bool
write_array_type_def(const array_type_def_sptr&	decl,
		     const string&			id,
		     write_context&			ctxt,
		     unsigned				indent)
{
  if (!decl)
    return false;

  annotate(decl, ctxt, indent);

  ostream& o = ctxt.get_ostream();

  do_indent(o, indent);
  o << "<array-type-def";

  o << " dimensions='" << decl->get_dimension_count() << "'";

  type_base_sptr element_type = decl->get_element_type();
  o << " type-id='" << ctxt.get_id_for_type(element_type) << "'";

  ctxt.record_type_as_referenced(element_type);

  write_array_size_and_alignment(decl, o);

  string i = id;
  if (i.empty())
    i = ctxt.get_id_for_type(decl);
  o << " id='" << i << "'";

  write_location(static_pointer_cast<decl_base>(decl), ctxt);

  if (!decl->get_dimension_count())
    o << "/>";
  else
    {
      o << ">\n";

      vector<array_type_def::subrange_sptr>::const_iterator si;

      for (si = decl->get_subranges().begin();
           si != decl->get_subranges().end(); ++si)
        {
	  unsigned local_indent =
	    indent + ctxt.get_config().get_xml_element_indent();
	  write_array_subrange_type(*si, ctxt, local_indent);
	  o << "\n";
	}

      do_indent(o, indent);
      o << "</array-type-def>";
    }

  ctxt.record_type_as_emitted(decl);

  return true;
}

/// Serialize a pointer to an instance of array_type_def.
///
/// @param decl the array_type_def to serialize.
///
/// @param ctxt the context of the serialization.
///
/// @param indent the number of indentation white spaces to use.
///
/// @return true upon succesful completion, false otherwise.
static bool
write_array_type_def(const array_type_def_sptr& decl,
		     write_context&		ctxt,
		     unsigned			indent)
{return write_array_type_def(decl, "", ctxt, indent);}

/// Serialize a pointer to an instance of enum_type_decl.
///
/// @param decl the enum_type_decl to serialize.
///
/// @param id the type id identitifier to use in the serialized
/// output.  If this is empty, the function will compute an
/// appropriate one.  This is useful when this function is called to
/// serialize the underlying type of a member type; in that case, the
/// caller has already computed the id of the *member type*, and that
/// id is the one to be written as the value of the 'id' attribute of
/// the XML element of the underlying type.
///
/// @param ctxt the context of the serialization.
///
/// @param indent the number of indentation white spaces to use.
///
/// @return true upon succesful completion, false otherwise.
static bool
write_enum_type_decl(const enum_type_decl_sptr& decl,
		     const string&		id,
		     write_context&		ctxt,
		     unsigned			indent)
{
  if (!decl)
    return false;

  annotate(decl->get_canonical_type(), ctxt, indent);

  ostream& o = ctxt.get_ostream();

  do_indent(o, indent);
  o << "<enum-decl name='" << xml::escape_xml_string(decl->get_name()) << "'";

  write_is_anonymous(decl, o);

  if (!decl->get_linkage_name().empty())
    o << " linkage-name='" << decl->get_linkage_name() << "'";

  write_location(decl, ctxt);

  string i = id;
  if (i.empty())
    i = ctxt.get_id_for_type(decl);
  o << " id='" << i << "'>\n";

  do_indent(o, indent + ctxt.get_config().get_xml_element_indent());
  o << "<underlying-type type-id='"
    << ctxt.get_id_for_type(decl->get_underlying_type())
    << "'/>\n";

  for (enum_type_decl::enumerators::const_iterator i =
	 decl->get_enumerators().begin();
       i != decl->get_enumerators().end();
       ++i)
    {
      do_indent(o, indent + ctxt.get_config().get_xml_element_indent());
      o << "<enumerator name='"
	<< i->get_name()
	<< "' value='"
	<< i->get_value()
	<< "'/>\n";
    }

  do_indent(o, indent);
  o << "</enum-decl>";

  ctxt.record_type_as_emitted(decl);

  return true;
}

/// Serialize a pointer to an instance of enum_type_decl.
///
/// @param decl the enum_type_decl to serialize.
///
/// @param ctxt the context of the serialization.
///
/// @param indent the number of indentation white spaces to use.
///
/// @return true upon succesful completion, false otherwise.
static bool
write_enum_type_decl(const enum_type_decl_sptr& decl,
		     write_context&		ctxt,
		     unsigned			indent)
{return write_enum_type_decl(decl, "", ctxt, indent);}

/// Serialize an @ref elf_symbol to an XML element of name
/// 'elf-symbol'.
///
/// @param sym the elf symbol to serialize.
///
/// @param ctxt the read context to use.
///
/// @param indent the number of white spaces to use as indentation.
///
/// @return true iff the function completed successfully.
static bool
write_elf_symbol(const elf_symbol_sptr&	sym,
		 write_context&		ctxt,
		 unsigned			indent)
{
  if (!sym)
    return false;

  ostream &o = ctxt.get_ostream();

  annotate(sym, ctxt, indent);
  do_indent(o, indent);
  o << "<elf-symbol name='" << sym->get_name() << "'";
  if (sym->is_variable() && sym->get_size())
  o << " size='" << sym->get_size() << "'";

  if (!sym->get_version().is_empty())
    {
      o << " version='" << sym->get_version().str() << "'";
      o << " is-default-version='";
      if (sym->get_version().is_default())
	o <<  "yes";
      else
	o << "no";
      o << "'";
    }

  write_elf_symbol_type(sym->get_type(), o);

  write_elf_symbol_binding(sym->get_binding(), o);

  write_elf_symbol_visibility(sym->get_visibility(), o);

  write_elf_symbol_aliases(*sym, o);

  o << " is-defined='";
  if (sym->is_defined())
    o << "yes";
  else
    o << "no";
  o << "'";

  if (sym->is_common_symbol())
    o << " is-common='yes'";

  o << "/>";

  return true;
}

/// Write the elf symbol database to the output associated to the
/// current context.
///
/// @param syms the sorted elf symbol data to write out.
///
/// @param ctxt the context to consider.
///
/// @param indent the number of white spaces to use as indentation.
///
/// @return true upon successful completion.
static bool
write_elf_symbols_table(const elf_symbols&	syms,
			write_context&		ctxt,
			unsigned		indent)
{
  if (syms.empty())
    return false;

  ostream& o = ctxt.get_ostream();

  unordered_map<string, bool> emitted_syms;
  for (elf_symbols::const_iterator it = syms.begin(); it != syms.end(); ++it)
    {
      write_elf_symbol(*it, ctxt, indent);
      o << "\n";
    }

  return true;
}

/// Write a vector of dependency names for the current corpus we are
/// writting.
///
/// @param needed the vector of dependency names to write.
///
/// @param ctxt the write context to use for the writting.
///
/// @param indent the number of indendation spaces to use.
///
/// @return true upon successful completion, false otherwise.
static bool
write_elf_needed(const vector<string>&	needed,
		 write_context&	ctxt,
		 unsigned		indent)
{
  if (needed.empty())
    return false;

  ostream& o = ctxt.get_ostream();

  for (vector<string>::const_iterator i = needed.begin();
       i != needed.end();
       ++i)
    {
      if (i != needed.begin())
	o << "\n";
      do_indent(o, indent);
      o << "<dependency name='" << *i << "'/>";
    }
  return true;
}

/// Serialize a pointer to an instance of typedef_decl.
///
/// @param decl the typedef_decl to serialize.
///
/// @param id the type id identitifier to use in the serialized
/// output.  If this is empty, the function will compute an
/// appropriate one.  This is useful when this function is called to
/// serialize the underlying type of a member type; in that case, the
/// caller has already computed the id of the *member type*, and that
/// id is the one to be written as the value of the 'id' attribute of
/// the XML element of the underlying type.
///
/// @param ctxt the context of the serialization.
///
/// @param indent the number of indentation white spaces to use.
///
/// @return true upon succesful completion, false otherwise.
static bool
write_typedef_decl(const typedef_decl_sptr&	decl,
		   const string&		id,
		   write_context&		ctxt,
		   unsigned			indent)
{
  if (!decl)
    return false;

  ostream &o = ctxt.get_ostream();

  annotate(decl, ctxt, indent);

  do_indent(o, indent);

  o << "<typedef-decl name='"
    << xml::escape_xml_string(decl->get_name())
    << "'";

  type_base_sptr underlying_type = decl->get_underlying_type();
  string type_id = ctxt.get_id_for_type(underlying_type);
  o << " type-id='" <<  type_id << "'";
  ctxt.record_type_as_referenced(underlying_type);

  write_location(decl, ctxt);

  string i = id;
  if (i.empty())
    i = ctxt.get_id_for_type(decl);

  o << " id='" << i << "'/>";

  ctxt.record_type_as_emitted(decl);

  return true;
}

/// Serialize a pointer to an instance of typedef_decl.
///
/// @param decl the typedef_decl to serialize.
///
/// @param ctxt the context of the serialization.
///
/// @param indent the number of indentation white spaces to use.
///
/// @return true upon succesful completion, false otherwise.
static bool
write_typedef_decl(const typedef_decl_sptr&	decl,
		   write_context&		ctxt,
		   unsigned			indent)
{return write_typedef_decl(decl, "", ctxt, indent);}

/// Serialize a pointer to an instances of var_decl.
///
/// @param decl the var_decl to serialize.
///
/// @param ctxt the context of the serialization.
///
/// @param write_linkage_name if true, serialize the mangled name of
/// this variable.
///
/// @param indent the number of indentation white spaces to use.
///
/// @return true upon succesful completion, false otherwise.
static bool
write_var_decl(const var_decl_sptr& decl, write_context& ctxt,
	       bool write_linkage_name, unsigned indent)
{
  if (!decl)
    return false;

  annotate(decl, ctxt, indent);

  ostream &o = ctxt.get_ostream();

  do_indent(o, indent);

  o << "<var-decl name='" << xml::escape_xml_string(decl->get_name()) << "'";
  type_base_sptr var_type = decl->get_type();
  o << " type-id='" << ctxt.get_id_for_type(var_type) << "'";
  ctxt.record_type_as_referenced(var_type);

  if (write_linkage_name)
    {
      const string& linkage_name = decl->get_linkage_name();
      if (!linkage_name.empty())
	o << " mangled-name='" << linkage_name << "'";
    }

  write_visibility(decl, o);

  write_binding(decl, o);

  write_location(decl, ctxt);

  write_elf_symbol_reference(decl->get_symbol(), o);

  o << "/>";

  ctxt.record_decl_as_emitted(decl);

  return true;
}

/// Serialize a pointer to a function_decl.
///
/// @param decl the pointer to function_decl to serialize.
///
/// @param ctxt the context of the serialization.
///
/// @param skip_first_parm if true, do not serialize the first
/// parameter of the function decl.
///
/// @param indent the number of indentation white spaces to use.
///
/// @return true upon succesful completion, false otherwise.
static bool
write_function_decl(const function_decl_sptr& decl, write_context& ctxt,
		    bool skip_first_parm, unsigned indent)
{
  if (!decl)
    return false;

  annotate(decl, ctxt, indent);

  ostream &o = ctxt.get_ostream();

  do_indent(o, indent);

  o << "<function-decl name='"
    << xml::escape_xml_string(decl->get_name())
    << "'";

  if (!decl->get_linkage_name().empty())
    o << " mangled-name='"
      << xml::escape_xml_string(decl->get_linkage_name()) << "'";

  write_location(decl, ctxt);

  if (decl->is_declared_inline())
    o << " declared-inline='yes'";

  write_visibility(decl, o);

  write_binding(decl, o);

  write_size_and_alignment(decl->get_type(), o);
  write_elf_symbol_reference(decl->get_symbol(), o);

  o << ">\n";

  type_base_sptr parm_type;
  vector<shared_ptr<function_decl::parameter> >::const_iterator pi =
    decl->get_parameters().begin();
  for ((skip_first_parm && pi != decl->get_parameters().end()) ? ++pi: pi;
       pi != decl->get_parameters().end();
       ++pi)
    {
      if ((*pi)->get_variadic_marker())
        {
          do_indent(o, indent + ctxt.get_config().get_xml_element_indent());
          o << "<parameter is-variadic='yes'";
        }
      else
	{
	  parm_type = (*pi)->get_type();

          annotate(*pi, ctxt,
		   indent + ctxt.get_config().get_xml_element_indent());

          do_indent(o, indent + ctxt.get_config().get_xml_element_indent());

	  o << "<parameter type-id='"
	    << ctxt.get_id_for_type(parm_type)
	    << "'";
	  ctxt.record_type_as_referenced(parm_type);

	  if (!(*pi)->get_name().empty())
	    o << " name='" << (*pi)->get_name() << "'";
	}
      if ((*pi)->get_artificial())
	  o << " is-artificial='yes'";
      write_location((*pi)->get_location(), ctxt);
      o << "/>\n";
    }

  if (shared_ptr<type_base> return_type = decl->get_return_type())
    {
      annotate(return_type , ctxt,
	       indent + ctxt.get_config().get_xml_element_indent());
      do_indent(o, indent + ctxt.get_config().get_xml_element_indent());
      o << "<return type-id='" << ctxt.get_id_for_type(return_type) << "'/>\n";
      ctxt.record_type_as_referenced(return_type);
    }

  do_indent(o, indent);
  o << "</function-decl>";

  ctxt.record_decl_as_emitted(decl);

  return true;
}

/// Serialize a function_type.
///
/// @param decl the pointer to function_type to serialize.
///
/// @param ctxt the context of the serialization.
///
/// @param indent the number of indentation white spaces to use.
///
/// @return true upon succesful completion, false otherwise.
static bool
write_function_type(const function_type_sptr& fn_type,
		    write_context& ctxt, unsigned indent)
{
  if (!fn_type)
    return false;

  ostream &o = ctxt.get_ostream();

  annotate(fn_type, ctxt, indent);

  do_indent(o, indent);

  o << "<function-type";

  write_size_and_alignment(fn_type, o);

  if (method_type_sptr method_type = is_method_type(fn_type))
    {
      o << " method-class-id='"
	<< ctxt.get_id_for_type(method_type->get_class_type())
	<< "'";

      write_cdtor_const_static(/*is_ctor=*/false, /*is_dtor=*/false,
			       /*is_const=*/method_type->get_is_const(),
			       /*is_static=*/false, o);
    }

  interned_string id = ctxt.get_id_for_type(fn_type);

  o << " id='"
    <<  id << "'";
  o << ">\n";

  type_base_sptr parm_type;
  for (vector<function_decl::parameter_sptr>::const_iterator pi =
	 fn_type->get_parameters().begin();
       pi != fn_type->get_parameters().end();
       ++pi)
    {

      if ((*pi)->get_variadic_marker())
        {
          do_indent(o, indent + ctxt.get_config().get_xml_element_indent());
          o << "<parameter is-variadic='yes'";
        }
      else
	{
	  parm_type = (*pi)->get_type();

          annotate(*pi, ctxt, indent + ctxt.get_config().get_xml_element_indent());

          do_indent(o, indent + ctxt.get_config().get_xml_element_indent());
	  o << "<parameter type-id='"
	    << ctxt.get_id_for_type(parm_type)
	    << "'";
	  ctxt.record_type_as_referenced(parm_type);

	  if (!(*pi)->get_name().empty())
	    {
	      string name = xml::escape_xml_string((*pi)->get_name());
	      o << " name='" << name << "'";
	    }
	}
      if ((*pi)->get_artificial())
	o << " is-artificial='yes'";
      o << "/>\n";
    }

  if (type_base_sptr return_type = fn_type->get_return_type())
    {
      annotate(return_type, ctxt, indent + ctxt.get_config().get_xml_element_indent());
      do_indent(o, indent + ctxt.get_config().get_xml_element_indent());
      o << "<return type-id='" << ctxt.get_id_for_type(return_type) << "'/>\n";
      ctxt.record_type_as_referenced(return_type);
    }

  do_indent(o, indent);
  o << "</function-type>";

  ctxt.record_type_as_emitted(fn_type);
  return true;
}

/// Write the opening tag of a 'class-decl' element.
///
/// @param decl the class declaration to serialize.
///
/// @param the type ID to use for the 'class-decl' element,, or empty
/// if we need to build a new one.
///
/// @param ctxt the write context to use.
///
/// @param indent the number of white space to use for indentation.
///
/// @param prepare_to_handle_members if set to true, then this function
/// figures out if the opening tag should be for an empty element or
/// not.  If set to false, then the opening tag is unconditionnaly for
/// a non-empty element.
///
/// @return true upon successful completion.
static bool
write_class_decl_opening_tag(const class_decl_sptr&	decl,
			     const string&		id,
			     write_context&		ctxt,
			     unsigned			indent,
			     bool			prepare_to_handle_members)
{
  if (!decl)
    return false;

  ostream& o = ctxt.get_ostream();

  do_indent_to_level(ctxt, indent, 0);

  o << "<class-decl name='" << xml::escape_xml_string(decl->get_name()) << "'";

  write_size_and_alignment(decl, o);

  write_is_struct(decl, o);

  write_is_anonymous(decl, o);

  write_naming_typedef(decl, ctxt);

  write_visibility(decl, o);

  write_location(decl, ctxt);

  write_class_or_union_is_declaration_only(decl, o);

  if (decl->get_earlier_declaration())
    {
      // This instance is the definition of an earlier declaration.
      o << " def-of-decl-id='"
	<< ctxt.get_id_for_type(is_type(decl->get_earlier_declaration()))
	<< "'";
    }

  string i = id;
  if (i.empty())
    i = ctxt.get_id_for_type(decl);
  o << " id='" << i << "'";

  if (!prepare_to_handle_members)
    o << ">\n";
  else
    {
      if (decl->has_no_base_nor_member())
	o << "/>";
      else
	o << ">\n";
    }

  return true;
}

/// Write the opening tag of a 'union-decl' element.
///
/// @param decl the union declaration to serialize.
///
/// @param the type ID to use for the 'union-decl' element, or empty
/// if we need to build a new one.
///
/// @param ctxt the write context to use.
///
/// @param indent the number of white space to use for indentation.
///
/// @param prepare_to_handle_members if set to true, then this function
/// figures out if the opening tag should be for an empty element or
/// not.  If set to false, then the opening tag is unconditionnaly for
/// a non-empty element.
///
/// @return true upon successful completion.
static bool
write_union_decl_opening_tag(const union_decl_sptr&	decl,
			     const string&		id,
			     write_context&		ctxt,
			     unsigned			indent,
			     bool			prepare_to_handle_members)
{
  if (!decl)
    return false;

  ostream& o = ctxt.get_ostream();

  do_indent_to_level(ctxt, indent, 0);

  o << "<union-decl name='" << xml::escape_xml_string(decl->get_name()) << "'";

  if (!decl->get_is_declaration_only())
    write_size_and_alignment(decl, o);

  write_is_anonymous(decl, o);

  write_visibility(decl, o);

  write_location(decl, ctxt);

  write_class_or_union_is_declaration_only(decl, o);

  string i = id;
  if (i.empty())
    i = ctxt.get_id_for_type(decl);
  o << " id='" << i << "'";

  if (!prepare_to_handle_members)
    o << ">\n";
  else
    {
      if (decl->has_no_member())
	o << "/>";
      else
	o << ">\n";
    }

  return true;
}

/// Serialize a class_decl type.
///
/// @param decl the pointer to class_decl to serialize.
///
/// @param id the type id identitifier to use in the serialized
/// output.  If this is empty, the function will compute an
/// appropriate one.  This is useful when this function is called to
/// serialize the underlying type of a member type; in that case, the
/// caller has already computed the id of the *member type*, and that
/// id is the one to be written as the value of the 'id' attribute of
/// the XML element of the underlying type.
///
/// @param ctxt the context of the serialization.
///
/// @param indent the initial indentation to use.
static bool
write_class_decl(const class_decl_sptr& decl,
		 const string&		id,
		 write_context&	ctxt,
		 unsigned		indent)
{
  if (!decl)
    return false;

  annotate(decl, ctxt, indent);

  ostream& o = ctxt.get_ostream();

  write_class_decl_opening_tag(decl, id, ctxt, indent,
			       /*prepare_to_handle_members=*/true);

  if (!decl->has_no_base_nor_member())
    {
      unsigned nb_ws = get_indent_to_level(ctxt, indent, 1);
      type_base_sptr base_type;
      for (class_decl::base_specs::const_iterator base =
	     decl->get_base_specifiers().begin();
	   base != decl->get_base_specifiers().end();
	   ++base)
	{
          annotate((*base)->get_base_class(), ctxt, indent);
	  do_indent(o, nb_ws);
	  o << "<base-class";

	  write_access((*base)->get_access_specifier(), o);

	  write_layout_offset (*base, o);

	  if ((*base)->get_is_virtual ())
	    o << " is-virtual='yes'";

	  base_type = (*base)->get_base_class();
	  o << " type-id='"
	    << ctxt.get_id_for_type(base_type)
	    << "'/>\n";

	  ctxt.record_type_as_referenced(base_type);
	}

      for (class_decl::member_types::const_iterator ti =
	     decl->get_member_types().begin();
	   ti != decl->get_member_types().end();
	   ++ti)
	write_member_type(*ti, ctxt, nb_ws);

      for (class_decl::data_members::const_iterator data =
	     decl->get_data_members().begin();
	   data != decl->get_data_members().end();
	   ++data)
	{
	  do_indent(o, nb_ws);
	  o << "<data-member";
	  write_access(get_member_access_specifier(*data), o);

	  bool is_static = get_member_is_static(*data);
	  write_cdtor_const_static(/*is_ctor=*/false,
				   /*is_dtor=*/false,
				   /*is_const=*/false,
				   /*is_static=*/is_static,
				   o);
	  write_layout_offset(*data, o);
	  o << ">\n";

	  write_var_decl(*data, ctxt, is_static,
			 get_indent_to_level(ctxt, indent, 2));
	  o << "\n";

	  do_indent_to_level(ctxt, indent, 1);
	  o << "</data-member>\n";
	}

      for (class_decl::member_functions::const_iterator f =
	     decl->get_member_functions().begin();
	   f != decl->get_member_functions().end();
	   ++f)
	{
	  function_decl_sptr fn = *f;
	  if (get_member_function_is_virtual(fn))
	    // All virtual member functions are emitted together,
	    // later.
	    continue;

	  ABG_ASSERT(!get_member_function_is_virtual(fn));

	  do_indent(o, nb_ws);
	  o << "<member-function";
	  write_access(get_member_access_specifier(fn), o);
	  write_cdtor_const_static( get_member_function_is_ctor(fn),
				    get_member_function_is_dtor(fn),
				    get_member_function_is_const(fn),
				    get_member_is_static(fn),
				    o);
	  o << ">\n";

	  write_function_decl(fn, ctxt,
			      /*skip_first_parameter=*/false,
			      get_indent_to_level(ctxt, indent, 2));
	  o << "\n";

	  do_indent_to_level(ctxt, indent, 1);
	  o << "</member-function>\n";
	}

      for (class_decl::member_functions::const_iterator f =
	     decl->get_virtual_mem_fns().begin();
	   f != decl->get_virtual_mem_fns().end();
	   ++f)
	{
	  function_decl_sptr fn = *f;

	  ABG_ASSERT(get_member_function_is_virtual(fn));

	  do_indent(o, nb_ws);
	  o << "<member-function";
	  write_access(get_member_access_specifier(fn), o);
	  write_cdtor_const_static( get_member_function_is_ctor(fn),
				    get_member_function_is_dtor(fn),
				    get_member_function_is_const(fn),
				    get_member_is_static(fn),
				    o);
	  write_voffset(fn, o);
	  o << ">\n";

	  write_function_decl(fn, ctxt,
			      /*skip_first_parameter=*/false,
			      get_indent_to_level(ctxt, indent, 2));
	  o << "\n";

	  do_indent_to_level(ctxt, indent, 1);
	  o << "</member-function>\n";
	}

      for (member_function_templates::const_iterator fn =
	     decl->get_member_function_templates().begin();
	   fn != decl->get_member_function_templates().end();
	   ++fn)
	{
	  do_indent(o, nb_ws);
	  o << "<member-template";
	  write_access((*fn)->get_access_specifier(), o);
	  write_cdtor_const_static((*fn)->is_constructor(),
				   /*is_dtor=*/false,
				   (*fn)->is_const(),
				   (*fn)->get_is_static(), o);
	  o << ">\n";
	  write_function_tdecl((*fn)->as_function_tdecl(), ctxt,
			       get_indent_to_level(ctxt, indent, 2));
	  o << "\n";
	  do_indent(o, nb_ws);
	  o << "</member-template>\n";
	}

      for (member_class_templates::const_iterator cl =
	     decl->get_member_class_templates().begin();
	   cl != decl->get_member_class_templates().end();
	   ++cl)
	{
	  do_indent(o, nb_ws);
	  o << "<member-template";
	  write_access((*cl)->get_access_specifier(), o);
	  write_cdtor_const_static(false, false, false,
				   (*cl)->get_is_static(), o);
	  o << ">\n";
	  write_class_tdecl((*cl)->as_class_tdecl(), ctxt,
			    get_indent_to_level(ctxt, indent, 2));
	  o << "\n";
	  do_indent(o, nb_ws);
	  o << "</member-template>\n";
	}

      do_indent_to_level(ctxt, indent, 0);

      o << "</class-decl>";
    }

  // We allow several *declarations* of the same class in the corpus,
  // but only one definition.
  if (!decl->get_is_declaration_only())
    ctxt.record_type_as_emitted(decl);
  else
    ctxt.record_decl_only_type_as_emitted(decl);

  return true;
}

/// Serialize a class_decl type.
///
/// @param decl the pointer to class_decl to serialize.
///
/// @param ctxt the context of the serialization.
///
/// @param indent the initial indentation to use.
///
/// @return true upon successful completion.
static bool
write_class_decl(const class_decl_sptr& decl,
		 write_context&	ctxt,
		 unsigned		indent)
{return write_class_decl(decl, "", ctxt, indent);}

/// Serialize a @ref union_decl type.
///
/// @param decl the pointer to @ref union_decl to serialize.
///
/// @param ctxt the context of the serialization.
///
/// @param indent the initial indentation to use.
///
/// @return true upon successful completion.
static bool
write_union_decl(const union_decl_sptr& decl,
		 const string& id,
		 write_context& ctxt,
		 unsigned indent)
{
  if (!decl)
    return false;

  annotate(decl, ctxt, indent);

  ostream& o = ctxt.get_ostream();

  write_union_decl_opening_tag(decl, id, ctxt, indent,
			       /*prepare_to_handle_members=*/true);
  if (!decl->has_no_member())
    {
      unsigned nb_ws = get_indent_to_level(ctxt, indent, 1);
      for (class_decl::member_types::const_iterator ti =
	     decl->get_member_types().begin();
	   ti != decl->get_member_types().end();
	   ++ti)
	write_member_type(*ti, ctxt, nb_ws);

      for (union_decl::data_members::const_iterator data =
	     decl->get_data_members().begin();
	   data != decl->get_data_members().end();
	   ++data)
	{
	  do_indent(o, nb_ws);
	  o << "<data-member";
	  write_access(get_member_access_specifier(*data), o);

	  bool is_static = get_member_is_static(*data);
	  write_cdtor_const_static(/*is_ctor=*/false,
				   /*is_dtor=*/false,
				   /*is_const=*/false,
				   /*is_static=*/is_static,
				   o);
	  o << ">\n";

	  write_var_decl(*data, ctxt, is_static,
			 get_indent_to_level(ctxt, indent, 2));
	  o << "\n";

	  do_indent_to_level(ctxt, indent, 1);
	  o << "</data-member>\n";
	}

      for (union_decl::member_functions::const_iterator f =
	     decl->get_member_functions().begin();
	   f != decl->get_member_functions().end();
	   ++f)
	{
	  function_decl_sptr fn = *f;
	  if (get_member_function_is_virtual(fn))
	    // All virtual member functions are emitted together,
	    // later.
	    continue;

	  ABG_ASSERT(!get_member_function_is_virtual(fn));

	  do_indent(o, nb_ws);
	  o << "<member-function";
	  write_access(get_member_access_specifier(fn), o);
	  write_cdtor_const_static( get_member_function_is_ctor(fn),
				    get_member_function_is_dtor(fn),
				    get_member_function_is_const(fn),
				    get_member_is_static(fn),
				    o);
	  o << ">\n";

	  write_function_decl(fn, ctxt,
			      /*skip_first_parameter=*/false,
			      get_indent_to_level(ctxt, indent, 2));
	  o << "\n";

	  do_indent_to_level(ctxt, indent, 1);
	  o << "</member-function>\n";
	}

      for (member_function_templates::const_iterator fn =
	     decl->get_member_function_templates().begin();
	   fn != decl->get_member_function_templates().end();
	   ++fn)
	{
	  do_indent(o, nb_ws);
	  o << "<member-template";
	  write_access((*fn)->get_access_specifier(), o);
	  write_cdtor_const_static((*fn)->is_constructor(),
				   /*is_dtor=*/false,
				   (*fn)->is_const(),
				   (*fn)->get_is_static(), o);
	  o << ">\n";
	  write_function_tdecl((*fn)->as_function_tdecl(), ctxt,
			       get_indent_to_level(ctxt, indent, 2));
	  o << "\n";
	  do_indent(o, nb_ws);
	  o << "</member-template>\n";
	}

      for (member_class_templates::const_iterator cl =
	     decl->get_member_class_templates().begin();
	   cl != decl->get_member_class_templates().end();
	   ++cl)
	{
	  do_indent(o, nb_ws);
	  o << "<member-template";
	  write_access((*cl)->get_access_specifier(), o);
	  write_cdtor_const_static(false, false, false,
				   (*cl)->get_is_static(), o);
	  o << ">\n";
	  write_class_tdecl((*cl)->as_class_tdecl(), ctxt,
			    get_indent_to_level(ctxt, indent, 2));
	  o << "\n";
	  do_indent(o, nb_ws);
	  o << "</member-template>\n";
	}

      do_indent_to_level(ctxt, indent, 0);

      o << "</union-decl>";
    }

  // We allow several *declarations* of the same union in the corpus,
  // but only one definition.
  if (!decl->get_is_declaration_only())
    ctxt.record_type_as_emitted(decl);
  else
    ctxt.record_decl_only_type_as_emitted(decl);

  return true;
}

static bool
write_union_decl(const union_decl_sptr& decl,
		 write_context& ctxt,
		 unsigned indent)
{return write_union_decl(decl, "", ctxt, indent);}

/// Write the opening tag for a 'member-type' element.
///
/// @param t the member type to consider.
///
/// @param ctxt the write context to use.
///
/// @param indent the number of white spaces to use for indentation.
///
/// @return true upon successful completion.
static bool
write_member_type_opening_tag(const type_base_sptr& t,
			      write_context& ctxt,
			      unsigned indent)
{
  ostream& o = ctxt.get_ostream();

  do_indent_to_level(ctxt, indent, 0);

  decl_base_sptr decl = get_type_declaration(t);
  ABG_ASSERT(decl);

  o << "<member-type";
  write_access(decl, o);
  o << ">";

  return true;
}

/// Serialize a member type.
///
/// Note that the id written as the value of the 'id' attribute of the
/// underlying type is actually the id of the member type, not the one
/// for the underying type.  That id takes in account, the access
/// specifier and the qualified name of the member type.
///
/// @param decl the declaration of the member type to serialize.
///
/// @param ctxt the write context to use.
///
/// @param indent the number of levels to use for indentation
static bool
write_member_type(const type_base_sptr& t, write_context& ctxt, unsigned indent)
{
  if (!t)
    return false;

  ostream& o = ctxt.get_ostream();

  write_member_type_opening_tag(t, ctxt, indent);
  o << "\n";

  string id = ctxt.get_id_for_type(t);

  unsigned nb_ws = get_indent_to_level(ctxt, indent, 1);
  ABG_ASSERT(write_qualified_type_def(dynamic_pointer_cast<qualified_type_def>(t),
				  id, ctxt, nb_ws)
	 || write_pointer_type_def(dynamic_pointer_cast<pointer_type_def>(t),
				   id, ctxt, nb_ws)
	 || write_reference_type_def(dynamic_pointer_cast<reference_type_def>(t),
				     id, ctxt, nb_ws)
	 || write_array_type_def(dynamic_pointer_cast<array_type_def>(t),
			         id, ctxt, nb_ws)
	 || write_enum_type_decl(dynamic_pointer_cast<enum_type_decl>(t),
				 id, ctxt, nb_ws)
	 || write_typedef_decl(dynamic_pointer_cast<typedef_decl>(t),
			       id, ctxt, nb_ws)
	 || write_union_decl(dynamic_pointer_cast<union_decl>(t),
			     id, ctxt, nb_ws)
	 || write_class_decl(dynamic_pointer_cast<class_decl>(t),
			     id, ctxt, nb_ws));
  o << "\n";

  do_indent_to_level(ctxt, indent, 0);
  o << "</member-type>\n";

  return true;
}

/// Serialize an instance of type_tparameter.
///
/// @param decl the instance to serialize.
///
/// @param ctxt the context of the serialization.
///
/// @param indent the initial indentation to use.
///
/// @return true upon successful completion, false otherwise.
static bool
write_type_tparameter(const type_tparameter_sptr	decl,
		      write_context&			ctxt,
		      unsigned				indent)
{
  if (!decl)
    return false;

  ostream &o = ctxt.get_ostream();
  do_indent_to_level(ctxt, indent, 0);

  string id_attr_name;
  if (ctxt.type_has_existing_id(decl))
    id_attr_name = "type-id";
  else
    id_attr_name = "id";

  o << "<template-type-parameter "
    << id_attr_name << "='" <<  ctxt.get_id_for_type(decl) << "'";

  std::string name = xml::escape_xml_string(decl->get_name ());
  if (!name.empty())
    o << " name='" << name << "'";

  write_location(decl, ctxt);

  o << "/>";

  ctxt.record_type_as_emitted(decl);

  return true;
}

/// Serialize an instance of non_type_tparameter.
///
/// @param decl the instance to serialize.
///
/// @param ctxt the context of the serialization.
///
/// @param indent the intial indentation to use.
///
/// @return true open successful completion, false otherwise.
static bool
write_non_type_tparameter(
 const shared_ptr<non_type_tparameter>	decl,
 write_context&	ctxt, unsigned indent)
{
  if (!decl)
    return false;

  ostream &o = ctxt.get_ostream();
  do_indent_to_level(ctxt, indent, 0);

  o << "<template-non-type-parameter type-id='"
    << ctxt.get_id_for_type(decl->get_type())
    << "'";

  string name = xml::escape_xml_string(decl->get_name());
  if (!name.empty())
    o << " name='" << name << "'";

  write_location(decl, ctxt);

  o << "/>";

  return true;
}

/// Serialize an instance of template template parameter.
///
/// @param decl the instance to serialize.
///
/// @param ctxt the context of the serialization.
///
/// @param indent the initial indentation to use.
///
/// @return true upon successful completion, false otherwise.

static bool
write_template_tparameter (const template_tparameter_sptr	decl,
			   write_context&			ctxt,
			   unsigned				indent)
{
  if (!decl)
    return false;

  ostream& o = ctxt.get_ostream();
  do_indent_to_level(ctxt, indent, 0);

  string id_attr_name = "id";
  if (ctxt.type_has_existing_id(decl))
    id_attr_name = "type-id";

  o << "<template-template-parameter " << id_attr_name << "='"
    << ctxt.get_id_for_type(decl) << "'";

  string name = xml::escape_xml_string(decl->get_name());
  if (!name.empty())
    o << " name='" << name << "'";

  o << ">\n";

  unsigned nb_spaces = get_indent_to_level(ctxt, indent, 1);
  for (list<shared_ptr<template_parameter> >::const_iterator p =
	 decl->get_template_parameters().begin();
       p != decl->get_template_parameters().end();
       ++p)
    {
      write_template_parameter(decl, ctxt, nb_spaces);
      o <<"\n";
    }

  do_indent_to_level(ctxt, indent, 0);
  o << "</template-template-parameter>";

  ctxt.record_type_as_emitted(decl);

  return true;
}

/// Serialize an instance of type_composition.
///
/// @param decl the decl to serialize.
///
/// @param ctxt the context of the serialization.
///
/// @param indent the initial indentation to use.
///
/// @return true upon successful completion, false otherwise.
static bool
write_type_composition
(const shared_ptr<type_composition> decl,
 write_context& ctxt, unsigned indent)
{
  if (!decl)
    return false;

  ostream& o = ctxt.get_ostream();

  do_indent_to_level(ctxt, indent, 0);

  o << "<template-parameter-type-composition>\n";

  unsigned nb_spaces = get_indent_to_level(ctxt, indent, 1);
  (write_pointer_type_def
   (dynamic_pointer_cast<pointer_type_def>(decl->get_composed_type()),
			  ctxt, nb_spaces)
   || write_reference_type_def
   (dynamic_pointer_cast<reference_type_def>(decl->get_composed_type()),
    ctxt, nb_spaces)
   || write_array_type_def
   (dynamic_pointer_cast<array_type_def>(decl->get_composed_type()),
    ctxt, nb_spaces)
   || write_qualified_type_def
   (dynamic_pointer_cast<qualified_type_def>(decl->get_composed_type()),
    ctxt, nb_spaces));

  o << "\n";

  do_indent_to_level(ctxt, indent, 0);
  o << "</template-parameter-type-composition>";

  return true;
}

/// Serialize an instance of template_parameter.
///
/// @param decl the instance to serialize.
///
/// @param ctxt the context of the serialization.
///
/// @param indent the initial indentation to use.
///
/// @return true upon successful completion, false otherwise.
static bool
write_template_parameter(const shared_ptr<template_parameter> decl,
			 write_context& ctxt, unsigned indent)
{
  if ((!write_type_tparameter
       (dynamic_pointer_cast<type_tparameter>(decl), ctxt, indent))
      && (!write_non_type_tparameter
	  (dynamic_pointer_cast<non_type_tparameter>(decl),
	   ctxt, indent))
      && (!write_template_tparameter
	  (dynamic_pointer_cast<template_tparameter>(decl),
	   ctxt, indent))
      && (!write_type_composition
	  (dynamic_pointer_cast<type_composition>(decl),
	   ctxt, indent)))
    return false;

  return true;
}

/// Serialize the template parameters of the a given template.
///
/// @param tmpl the template for which to emit the template parameters.
static void
write_template_parameters(const shared_ptr<template_decl> tmpl,
			  write_context& ctxt, unsigned indent)
{
  if (!tmpl)
    return;

  ostream &o = ctxt.get_ostream();

  unsigned nb_spaces = get_indent_to_level(ctxt, indent, 1);
  for (list<shared_ptr<template_parameter> >::const_iterator p =
	 tmpl->get_template_parameters().begin();
       p != tmpl->get_template_parameters().end();
       ++p)
    {
      write_template_parameter(*p, ctxt, nb_spaces);
      o << "\n";
    }
}

/// Serialize an instance of function_tdecl.
///
/// @param decl the instance to serialize.
///
/// @param ctxt the context of the serialization
///
/// @param indent the initial indentation.
static bool
write_function_tdecl(const shared_ptr<function_tdecl> decl,
		     write_context& ctxt, unsigned indent)
{
  if (!decl)
    return false;

  ostream& o = ctxt.get_ostream();

  do_indent_to_level(ctxt, indent, 0);

  o << "<function-template-decl id='" << ctxt.get_id_for_fn_tmpl(decl) << "'";

  write_location(decl, ctxt);

  write_visibility(decl, o);

  write_binding(decl, o);

  o << ">\n";

  write_template_parameters(decl, ctxt, indent);

  write_function_decl(decl->get_pattern(), ctxt,
		      /*skip_first_parameter=*/false,
		      get_indent_to_level(ctxt, indent, 1));
  o << "\n";

  do_indent_to_level(ctxt, indent, 0);

  o << "</function-template-decl>";

  return true;
}


/// Serialize an instance of class_tdecl
///
/// @param decl a pointer to the instance of class_tdecl to serialize.
///
/// @param ctxt the context of the serializtion.
///
/// @param indent the initial number of white space to use for
/// indentation.
///
/// @return true upon successful completion, false otherwise.
static bool
write_class_tdecl(const shared_ptr<class_tdecl> decl,
		  write_context& ctxt, unsigned indent)
{
  if (!decl)
    return false;

  ostream& o = ctxt.get_ostream();

  do_indent_to_level(ctxt, indent, 0);

  o << "<class-template-decl id='" << ctxt.get_id_for_class_tmpl(decl) << "'";

  write_location(decl, ctxt);

  write_visibility(decl, o);

  o << ">\n";

  write_template_parameters(decl, ctxt, indent);

  write_class_decl(decl->get_pattern(), ctxt,
		   get_indent_to_level(ctxt, indent, 1));
  o << "\n";

  do_indent_to_level(ctxt, indent, 0);

  o << "</class-template-decl>";

  return true;
}

#ifdef WITH_ZIP_ARCHIVE

/// A context used by functions that write a corpus out to disk in a
/// ZIP archive of ABI Instrumentation XML files.
///
/// The aim of this context file is to hold the buffers of data that
/// are to be written into a given zip object, until the zip object is
/// closed.  It's at that point that the buffers data is really
/// flushed into the zip archive.
///
/// When an instance of this context type is created for a given zip
/// object, is created, its life time should be longer than the @ref
/// zip_sptr object it holds.
///
/// The definition of this type is private and should remain hidden
/// from client code.
struct archive_write_ctxt
{
  list<string> serialized_tus;
  zip_sptr archive;

  archive_write_ctxt(zip_sptr ar)
    : archive(ar)
  {}
};
typedef shared_ptr<archive_write_ctxt> archive_write_ctxt_sptr;

/// Create a write context to a given archive.  The result of this
/// function is to be passed to the functions that are to write a
/// corpus to an archive, e.g, write_corpus_to_archive().
///
/// @param archive_path the path to the archive to create this write
/// context for.
///
/// @return the resulting write context to pass to the functions that
/// are to write a corpus to @ref archive_path.
static archive_write_ctxt_sptr
create_archive_write_context(const string& archive_path)
{
  if (archive_path.empty())
    return archive_write_ctxt_sptr();

  int error_code = 0;
  zip_sptr archive = open_archive(archive_path,
				  ZIP_CREATE|ZIP_TRUNCATE|ZIP_CHECKCONS,
				  &error_code);
  if (error_code)
    return archive_write_ctxt_sptr();

  archive_write_ctxt_sptr r(new archive_write_ctxt(archive));
  return r;
}

/// Write a translation unit to an on-disk archive.  The archive is a
/// zip archive of ABI Instrumentation files in XML format.
///
/// @param tu the translation unit to serialize.
///
/// @param ctxt the context of the serialization.  Contains
/// information about where the archive is on disk, the zip archive,
/// and the buffers holding the temporary data to be flushed into the archive.
///
/// @param annotate whether ABIXML output should be annotated.
///
/// @return true upon succesful serialization occured, false
/// otherwise.
static bool
write_translation_unit_to_archive(const translation_unit& tu,
				  archive_write_ctxt& ctxt,
                                  const bool annotate)
{
  if (!ctxt.archive)
    return false;

  ostringstream os;
  if (!write_translation_unit(tu, /*indent=*/0, os, annotate))
    return false;
  ctxt.serialized_tus.push_back(os.str());

  zip_source *source;
  if ((source = zip_source_buffer(ctxt.archive.get(),
				  ctxt.serialized_tus.back().c_str(),
				  ctxt.serialized_tus.back().size(),
				  false)) == 0)
    return false;

  if (zip_file_add(ctxt.archive.get(), tu.get_path().c_str(), source,
		   ZIP_FL_OVERWRITE|ZIP_FL_ENC_GUESS) < 0)
    {
      zip_source_free(source);
      return false;
    }

  return true;
}

 /// Serialize a given corpus to disk in a file at a given path.
 ///
 /// @param tu the translation unit to serialize.
 ///
 /// @param ctxt the context of the serialization.  Contains
 /// information about where the archive is on disk, the zip archive
 /// object, and the buffers holding the temporary data to be flushed
 /// into the archive.
 ///
 /// @param annotate whether ABIXML output should be annotated.
 ///
 /// @return true upon successful completion, false otherwise.
static bool
write_corpus_to_archive(const corpus& corp,
			archive_write_ctxt& ctxt,
                        const bool annotate)
{
  for (translation_units::const_iterator i =
	 corp.get_translation_units().begin();
       i != corp.get_translation_units().end();
       ++i)
    {
      if (! write_translation_unit_to_archive(**i, ctxt, annotate))
	return false;
    }

  // TODO: ensure abi-info descriptor is added to the archive.
  return true;
}

/// Serialize a given corpus to disk in an archive file at a given
/// path.
///
/// @param corp the ABI corpus to serialize.
///
 /// @param ctxt the context of the serialization.  Contains
 /// information about where the archive is on disk, the zip archive
 /// object, and the buffers holding the temporary data to be flushed
 /// into the archive.
 ///
 /// @param annotate whether ABIXML output should be annotated.
 ///
 /// @return upon successful completion, false otherwise.
static bool
write_corpus_to_archive(const corpus& corp,
			archive_write_ctxt_sptr ctxt,
                        const bool annotate)
{return write_corpus_to_archive(corp, *ctxt, annotate);}

 /// Serialize the current corpus to disk in a file at a given path.
 ///
 /// @param tu the translation unit to serialize.
 ///
 /// @param path the path of the file to serialize the
 /// translation_unit to.
 ///
 /// @param annotate whether ABIXML output should be annotated.
 ///
 /// @return true upon successful completion, false otherwise.
bool
write_corpus_to_archive(const corpus& corp,
			const string& path,
                        const bool annotate)
{
  archive_write_ctxt_sptr ctxt = create_archive_write_context(path);
  ABG_ASSERT(ctxt);
  return write_corpus_to_archive(corp, ctxt, annotate);
}

 /// Serialize the current corpus to disk in a file.  The file path is
 /// given by translation_unit::get_path().
 ///
 /// @param tu the translation unit to serialize.
 ///
 /// @param annotate whether ABIXML output should be annotated.
 ///
 /// @return true upon successful completion, false otherwise.
bool
write_corpus_to_archive(const corpus& corp, const bool annotate)
{return write_corpus_to_archive(corp, corp.get_path(), annotate);}

 /// Serialize the current corpus to disk in a file.  The file path is
 /// given by translation_unit::get_path().
 ///
 /// @param tu the translation unit to serialize.
 ///
 /// @param annotate whether ABIXML output should be annotated.
 ///
 /// @return true upon successful completion, false otherwise.
bool
write_corpus_to_archive(const corpus_sptr corp, const bool annotate)
{return write_corpus_to_archive(*corp, annotate);}

#endif //WITH_ZIP_ARCHIVE

/// Serialize an ABI corpus to a single native xml document.  The root
/// note of the resulting XML document is 'abi-corpus'.
///
/// @param corpus the corpus to serialize.
///
/// @param indent the number of white space indentation to use.
///
/// @param ctxt the write context to use.
///
/// @return true upon successful completion, false otherwise.
bool
write_corpus(const corpus_sptr	corpus,
	     unsigned		indent,
	     write_context&	ctxt)
{
  if (!corpus)
    return false;

  do_indent_to_level(ctxt, indent, 0);

  std::ostream& out = ctxt.get_ostream();

  out << "<abi-corpus";
  if (!corpus->get_path().empty())
    out << " path='" << xml::escape_xml_string(corpus->get_path()) << "'";

  if (!corpus->get_architecture_name().empty())
    out << " architecture='" << corpus->get_architecture_name()<< "'";

  if (!corpus->get_soname().empty())
    out << " soname='" << corpus->get_soname()<< "'";

  if (corpus->is_empty())
    {
      out << "/>\n";
      return true;
    }

  out << ">\n";

  // Write the list of needed corpora.

  if (!corpus->get_needed().empty())
    {
      do_indent_to_level(ctxt, indent, 1);
      out << "<elf-needed>\n";
      write_elf_needed(corpus->get_needed(), ctxt,
		       get_indent_to_level(ctxt, indent, 2));
      out << "\n";
      do_indent_to_level(ctxt, indent, 1);
      out << "</elf-needed>\n";
    }

  // Write the function symbols data base.
  if (!corpus->get_fun_symbol_map().empty())
    {
      do_indent_to_level(ctxt, indent, 1);
      out << "<elf-function-symbols>\n";

      write_elf_symbols_table(corpus->get_sorted_fun_symbols(), ctxt,
			      get_indent_to_level(ctxt, indent, 2));

      do_indent_to_level(ctxt, indent, 1);
      out << "</elf-function-symbols>\n";
    }

  // Write the variable symbols data base.
  if (!corpus->get_var_symbol_map().empty())
    {
      do_indent_to_level(ctxt, indent, 1);
      out << "<elf-variable-symbols>\n";

      write_elf_symbols_table(corpus->get_sorted_var_symbols(), ctxt,
			      get_indent_to_level(ctxt, indent, 2));

      do_indent_to_level(ctxt, indent, 1);
      out << "</elf-variable-symbols>\n";
    }

  // Now write the translation units.
  for (translation_units::const_iterator i =
	 corpus->get_translation_units().begin();
       i != corpus->get_translation_units().end();
       ++i)
    {
      translation_unit& tu = **i;
      if (!tu.is_empty())
	write_translation_unit(ctxt, tu, get_indent_to_level(ctxt, indent, 1));
    }

  do_indent_to_level(ctxt, indent, 0);
  out << "</abi-corpus>\n";

  return true;
}

/// Serialize an ABI corpus to a single native xml document.  The root
/// note of the resulting XML document is 'abi-corpus'.
///
/// @param corpus the corpus to serialize.
///
/// @param indent the number of white space indentation to use.
///
/// @param out the output stream to serialize the ABI corpus to.
///
/// @param annotate whether ABIXML output should be annotated.
///
/// @return true upon successful completion, false otherwise.
bool
write_corpus(const corpus_sptr	corpus,
	     unsigned		indent,
	     std::ostream&	out,
	     const bool	annotate)
{
  if (!corpus)
    return false;

  write_context ctxt(corpus->get_environment(), out);
  set_annotate(ctxt, annotate);

  return write_corpus(corpus, indent, ctxt);
}

/// Serialize an ABI corpus group to a single native xml document.
/// The root note of the resulting XML document is 'abi-corpus-group'.
///
/// @param group the corpus group to serialize.
///
/// @param indent the number of white space indentation to use.
///
/// @param ctxt the write context to use.
///
/// @return true upon successful completion, false otherwise.
bool
write_corpus_group(const corpus_group_sptr&	group,
		   unsigned			indent,
		   write_context&		ctxt)

{
  if (!group)
    return false;

  do_indent_to_level(ctxt, indent, 0);

std::ostream& out = ctxt.get_ostream();

  out << "<abi-corpus-group";

  if (!group->get_path().empty())
    out << " path='" << xml::escape_xml_string(group->get_path()) << "'";

  if (!group->get_architecture_name().empty())
    out << " architecture='" << group->get_architecture_name()<< "'";

  if (group->is_empty())
    {
      out << "/>\n";
      return true;
    }

  out << ">\n";

  // Write the list of corpora
  for (corpus_group::corpora_type::const_iterator c =
	 group->get_corpora().begin();
       c != group->get_corpora().end();
       ++c)
    write_corpus(*c, get_indent_to_level(ctxt, indent, 1), ctxt);

  do_indent_to_level(ctxt, indent, 0);
  out << "</abi-corpus-group>\n";

  return true;
}

/// Serialize an ABI corpus group to a single native xml document.
/// The root note of the resulting XML document is 'abi-corpus-group'.
///
/// @param group the corpus group to serialize.
///
/// @param indent the number of white space indentation to use.
///
/// @param out the output stream to serialize the ABI corpus to.
///
/// @param annotate whether ABIXML output should be annotated.
///
/// @return true upon successful completion, false otherwise.
bool
write_corpus_group(const corpus_group_sptr&	group,
		   unsigned			indent,
		   std::ostream&		out,
		   const bool			annotate)

{
  if (!group)
    return false;

  write_context ctxt(group->get_environment(), out);
  set_annotate(ctxt, annotate);

  return write_corpus_group(group, indent, ctxt);
}

/// Serialize an ABI corpus to a single native xml document.  The root
/// note of the resulting XML document is 'abi-corpus'.
///
/// @param corpus the corpus to serialize.
///
/// @param indent the number of white space indentation to use.
///
/// @param path the output file to serialize the ABI corpus to.
///
/// @param annotate whether ABIXML output should be annotated.
///
/// @return true upon successful completion, false otherwise.
bool
write_corpus(const corpus_sptr	corpus,
	     unsigned		indent,
	     const string&	path,
	     const bool	annotate)
{
    bool result = true;

  try
    {
      ofstream of(path.c_str(), std::ios_base::trunc);
      if (!of.is_open())
	{
	  cerr << "failed to access " << path << "\n";
	  return false;
	}

      if (!write_corpus(corpus, indent, of, annotate))
	{
	  cerr << "failed to access " << path << "\n";
	  result = false;
	}

      of.close();
    }
  catch(...)
    {
      cerr << "failed to write to " << path << "\n";
      result = false;
    }

  return result;
}

} //end namespace xml_writer

// <Debugging routines>

using namespace abigail::ir;

/// Serialize a pointer to decl_base to an output stream.
///
/// @param d the pointer to decl_base to serialize.
///
/// @param o the output stream to consider.
///
/// @param annotate whether ABIXML output should be annotated.
void
dump(const decl_base_sptr d, std::ostream& o, const bool annotate)
{
  xml_writer::write_context ctxt(d->get_environment(), o);
  xml_writer::set_annotate(ctxt, annotate);
  write_decl(d, ctxt, /*indent=*/0);
  o << "\n";
}

/// Serialize a pointer to decl_base to stderr.
///
/// @param d the pointer to decl_base to serialize.
///
/// @param annotate whether ABIXML output should be annotated.
void
dump(const decl_base_sptr d, const bool annotate)
{dump(d, cerr, annotate);}

/// Serialize a pointer to type_base to an output stream.
///
/// @param t the pointer to type_base to serialize.
///
/// @param o the output stream to serialize the @ref type_base to.
///
/// @param annotate whether ABIXML output should be annotated.
void
dump(const type_base_sptr t, std::ostream& o, const bool annotate)
{dump(get_type_declaration(t), o, annotate);}

/// Serialize a pointer to type_base to stderr.
///
/// @param t the pointer to type_base to serialize.
///
/// @param annotate whether ABIXML output should be annotated.
void
dump(const type_base_sptr t, const bool annotate)
{dump(t, cerr, annotate);}

/// Serialize a pointer to var_decl to an output stream.
///
/// @param v the pointer to var_decl to serialize.
///
/// @param o the output stream to serialize the @ref var_decl to.
///
/// @param annotate whether ABIXML output should be annotated.
void
dump(const var_decl_sptr v, std::ostream& o, const bool annotate)
{
  xml_writer::write_context ctxt(v->get_environment(), o);
  xml_writer::set_annotate(ctxt, annotate);
  write_var_decl(v, ctxt, /*linkage_name*/true, /*indent=*/0);
  cerr << "\n";
}

/// Serialize a pointer to var_decl to stderr.
///
/// @param v the pointer to var_decl to serialize.
///
/// @param annotate whether ABIXML output should be annotated.
void
dump(const var_decl_sptr v, const bool annotate)
{dump(v, cerr, annotate);}

/// Serialize a @ref translation_unit to an output stream.
///
/// @param t the translation_unit to serialize.
///
/// @param o the outpout stream to serialize the translation_unit to.
///
/// @param annotate whether ABIXML output should be annotated.
void
dump(const translation_unit& t, std::ostream& o, const bool annotate)
{
  xml_writer::write_context ctxt(t.get_environment(), o);
  xml_writer::set_annotate(ctxt, annotate);
  write_translation_unit(ctxt, t, /*indent=*/0);
  o << "\n";
}

/// Serialize an instance of @ref translation_unit to stderr.
///
/// @param t the translation_unit to serialize.
void
dump(const translation_unit& t, const bool annotate)
{dump(t, cerr, annotate);}

/// Serialize a pointer to @ref translation_unit to an output stream.
///
/// @param t the @ref translation_unit_sptr to serialize.
///
/// @param o the output stream to serialize the translation unit to.
///
/// @param annotate whether ABIXML output should be annotated.
void
dump(const translation_unit_sptr t, std::ostream& o, const bool annotate)
{
  if (t)
    dump(*t, o, annotate);
}

/// Serialize a pointer to @ref translation_unit to stderr.
///
/// @param t the translation_unit_sptr to serialize.
///
/// @param annotate whether ABIXML output should be annotated.
void
dump(const translation_unit_sptr t, const bool annotate)
{
  if (t)
    dump(*t, annotate);
}

/// Serialize a source location to an output stream.
///
/// @param l the declaration to consider.
///
/// @param o the output stream to serialize to.
void
dump_location(const location& l, ostream& o)
{
  string path;
  unsigned line = 0, col = 0;

  l.expand(path, line, col);
  o << path << ":" << line << "," << col << "\n";
}

/// Serialize a source location for debugging purposes.
///
/// The location is serialized to the standard error output stream.
///
/// @param l the declaration to consider.
///
void
dump_location(const location& l)
{dump_location(l, cerr);}

/// Serialize the source location of a decl to an output stream for
/// debugging purposes.
///
/// @param d the declaration to consider.
///
/// @param o the output stream to serizalize the location to.
void
dump_decl_location(const decl_base& d, ostream& o)
{dump_location(d.get_location(), o);}

/// Serialize the source location of a decl to stderr for debugging
/// purposes.
///
/// @param d the declaration to consider.
void
dump_decl_location(const decl_base& d)
{dump_decl_location(d, cerr);}

/// Serialize the source location of a dcl to stderr for debugging
/// purposes.
///
/// @param d the declaration to consider.
void
dump_decl_location(const decl_base* d)
{
  if (d)
    dump_decl_location(*d);
}

/// Serialize the source location of a decl to stderr for debugging
/// purposes.
///
/// @param d the declaration to consider.
void
dump_decl_location(const decl_base_sptr d)
{dump_decl_location(d.get());}

// </Debugging routines>
} //end namespace abigail
