// -*- Mode: C++ -*-
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

bool
write_translation_unit(write_context&	       ctxt,
		       const translation_unit& tu,
		       const unsigned	       indent);

bool ABG_DEPRECATED
write_translation_unit(const translation_unit& tu,
		       unsigned		       indent,
		       std::ostream&	       out,
		       const bool	       annotate = false);

bool ABG_DEPRECATED
write_translation_unit(const translation_unit& tu,
		       unsigned		       indent,
		       const string&	       path,
		       const bool	       annotate = false);

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
write_corpus(write_context& ctxt, const corpus_sptr& corpus, unsigned indent);

bool ABG_DEPRECATED
write_corpus(const corpus_sptr& corpus, unsigned indent, write_context& ctxt);

bool ABG_DEPRECATED
write_corpus(const corpus_sptr corpus,
	     unsigned	       indent,
	     std::ostream&     out,
	     const bool	       annotate = false);

bool ABG_DEPRECATED
write_corpus(const corpus_sptr corpus,
	     unsigned	       indent,
	     const string&     path,
	     const bool	       annotate = false);

bool
write_corpus_group(write_context&	    ctx,
		   const corpus_group_sptr& group,
		   unsigned		    indent);

bool ABG_DEPRECATED
write_corpus_group(const corpus_group_sptr& group,
		   unsigned		    indent,
		   write_context&	    ctxt);

bool ABG_DEPRECATED
write_corpus_group(const corpus_group_sptr& group,
		   unsigned		    indent,
		   std::ostream&	    out,
		   const bool		    annotate = false);

bool ABG_DEPRECATED
write_corpus_group(const corpus_group_sptr& group,
		   unsigned		    indent,
		   const string&	    path,
		   const bool		    annotate = false);

}// end namespace xml_writer
}// end namespace abigail

#endif //  __ABG_WRITER_H__
