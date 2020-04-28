// -*- Mode: C++ -*-
//
// Copyright (C) 2013-2020 Red Hat, Inc.
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
// Author: Dodji Seketeli

/// @file
///
/// This file contains the declarations of the entry points to
/// de-serialize an instance of @ref abigail::translation_unit to an
/// ABI Instrumentation file in libabigail native XML format.

#ifndef __ABG_WRITER_H__
#define __ABG_WRITER_H__

#include "abg-fwd.h"

namespace abigail
{
namespace xml_writer
{

using namespace abigail::ir;

class write_context;

/// A convenience typedef for a shared pointer to write_context.
typedef shared_ptr<write_context> write_context_sptr;

write_context_sptr
create_write_context(const environment *env,
		     ostream& output_stream);

void
set_show_locs(write_context& ctxt, bool flag);

void
set_annotate(write_context& ctxt, bool flag);

void
set_write_architecture(write_context& ctxt, bool flag);

void
set_write_corpus_path(write_context& ctxt, bool flag);

void
set_write_comp_dir(write_context& ctxt, bool flag);

void
set_write_elf_needed(write_context& ctxt, bool flag);

void
set_short_locs(write_context& ctxt, bool flag);

void
set_write_parameter_names(write_context& ctxt, bool flag);

/// A convenience generic function to set common options (usually used
/// by Libabigail tools) from a generic options carrying-object, into
/// a given @ref write_context.
///
/// @param ctxt the @ref the write_context to consider.
///
/// @param opts the option-carrying object to set the options from.
/// It must contain data members named: annotate, and show_locs, at
/// very least.
template <typename OPTS>
void
set_common_options(write_context& ctxt, const OPTS& opts)
{
  set_annotate(ctxt, opts.annotate);
  set_show_locs(ctxt, opts.show_locs);
  set_write_architecture(ctxt, opts.write_architecture);
  set_write_corpus_path(ctxt, opts.write_corpus_path);
  set_write_comp_dir(ctxt, opts.write_comp_dir);
  set_write_elf_needed(ctxt, opts.write_elf_needed);
  set_write_parameter_names(ctxt, opts.write_parameter_names);
  set_short_locs(ctxt, opts.short_locs);
}

void
set_ostream(write_context& ctxt, ostream& os);

bool
write_translation_unit(write_context&	       ctxt,
		       const translation_unit& tu,
		       const unsigned	       indent);

bool
write_corpus_to_archive(const corpus& corp,
			const string& path,
			const bool  annotate = false);

bool
write_corpus_to_archive(const corpus& corp,
			const bool annotate = false);

bool
write_corpus_to_archive(const corpus_sptr corp,
			const bool annotate = false);

bool
write_corpus(write_context&	ctxt,
	     const corpus_sptr& corpus,
	     unsigned		indent,
	     bool		member_of_group = false);

bool
write_corpus_group(write_context&	    ctx,
		   const corpus_group_sptr& group,
		   unsigned		    indent);

}// end namespace xml_writer
}// end namespace abigail

#endif //  __ABG_WRITER_H__
