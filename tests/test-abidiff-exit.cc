// -*- Mode: C++ -*-
//
// Copyright (C) 2016-2020 Red Hat, Inc.
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

// Author: Dodji Seketeli

/// @file
///
/// This program runs abidiff between input files and checks that
/// the exit code of the abidiff is the one we expect.
///
/// The set of input files and reference reports to consider should be
/// present in the source distribution.

/// This is an aggregate that specifies where a test shall get its
/// input from and where it shall write its ouput to.

#include <sys/wait.h>
#include <cstring>
#include <string>
#include <fstream>
#include <iostream>
#include <cstdlib>
#include "abg-tools-utils.h"
#include "test-utils.h"

using abigail::tools_utils::abidiff_status;

struct InOutSpec
{
  const char*	in_elfv0_path;
  const char*	in_elfv1_path;
  const char*	in_suppr_path;
  const char*	abidiff_options;
  abidiff_status status;
  const char*	in_report_path;
  const char*	out_report_path;
};// end struct InOutSpec;

InOutSpec in_out_specs[] =
{
  {
    "data/test-abidiff-exit/test1-voffset-change-v0.o",
    "data/test-abidiff-exit/test1-voffset-change-v1.o",
    "",
    "--no-default-suppression --no-show-locs",
    abigail::tools_utils::ABIDIFF_ABI_CHANGE
    | abigail::tools_utils::ABIDIFF_ABI_INCOMPATIBLE_CHANGE,
    "data/test-abidiff-exit/test1-voffset-change-report0.txt",
    "output/test-abidiff-exit/test1-voffset-change-report0.txt"
  },
  {
    "data/test-abidiff-exit/test1-voffset-change-v0.o",
    "data/test-abidiff-exit/test1-voffset-change-v1.o",
    "data/test-abidiff-exit/test1-voffset-change.abignore",
    "--no-default-suppression --no-show-locs",
    abigail::tools_utils::ABIDIFF_OK,
    "data/test-abidiff-exit/test1-voffset-change-report1.txt",
    "output/test-abidiff-exit/test1-voffset-change-report1.txt"
  },
  {
    "data/test-abidiff-exit/test2-filtered-removed-fns-v0.o",
    "data/test-abidiff-exit/test2-filtered-removed-fns-v1.o",
    "",
    "--no-default-suppression --no-show-locs",
    abigail::tools_utils::ABIDIFF_ABI_CHANGE
    | abigail::tools_utils::ABIDIFF_ABI_INCOMPATIBLE_CHANGE,
    "data/test-abidiff-exit/test2-filtered-removed-fns-report0.txt",
    "output/test-abidiff-exit/test2-filtered-removed-fns-report0.txt"
  },
  {
    "data/test-abidiff-exit/test2-filtered-removed-fns-v0.o",
    "data/test-abidiff-exit/test2-filtered-removed-fns-v1.o",
    "data/test-abidiff-exit/test2-filtered-removed-fns.abignore",
    "--no-default-suppression --no-show-locs",
    abigail::tools_utils::ABIDIFF_OK,
    "data/test-abidiff-exit/test2-filtered-removed-fns-report1.txt",
    "output/test-abidiff-exit/test2-filtered-removed-fns-report1.txt"
  },
  {
    "data/test-abidiff-exit/test-loc-v0.bi",
    "data/test-abidiff-exit/test-loc-v1.bi",
    "",
    "",
    abigail::tools_utils::ABIDIFF_ABI_CHANGE,
    "data/test-abidiff-exit/test-loc-with-locs-report.txt",
    "output/test-abidiff-exit/test-loc-with-locs-report.txt"
  },
  {
    "data/test-abidiff-exit/test-loc-v0.bi",
    "data/test-abidiff-exit/test-loc-v1.bi",
    "",
    "--no-show-locs",
    abigail::tools_utils::ABIDIFF_ABI_CHANGE,
    "data/test-abidiff-exit/test-loc-without-locs-report.txt",
    "output/test-abidiff-exit/test-loc-without-locs-report.txt"
  },
  {
    "data/test-abidiff-exit/test-no-stray-comma-v0.o",
    "data/test-abidiff-exit/test-no-stray-comma-v1.o",
    "",
    "--leaf-changes-only",
    abigail::tools_utils::ABIDIFF_ABI_CHANGE,
    "data/test-abidiff-exit/test-no-stray-comma-report.txt",
    "output/test-abidiff-exit/test-no-stray-comma-report.txt"
  },
  {
    "data/test-abidiff-exit/test-leaf0-v0.o",
    "data/test-abidiff-exit/test-leaf0-v1.o",
    "",
    "--no-show-locs --leaf-changes-only",
    abigail::tools_utils::ABIDIFF_ABI_CHANGE,
    "data/test-abidiff-exit/test-leaf0-report.txt",
    "output/test-abidiff-exit/test-leaf0-report.txt"
  },
  {0, 0, 0 ,0,  abigail::tools_utils::ABIDIFF_OK, 0, 0}
};

int
main()
{
  using std::string;
  using std::cerr;
  using abigail::tests::get_src_dir;
  using abigail::tests::get_build_dir;
  using abigail::tools_utils::ensure_parent_dir_created;
  using abigail::tools_utils::abidiff_status;

  bool is_ok = true;
  string in_elfv0_path, in_elfv1_path,
    in_suppression_path, abidiff_options, abidiff, cmd,
    ref_diff_report_path, out_diff_report_path;

    for (InOutSpec* s = in_out_specs; s->in_elfv0_path; ++s)
      {
	in_elfv0_path = string(get_src_dir()) + "/tests/" + s->in_elfv0_path;
	in_elfv1_path = string(get_src_dir()) + "/tests/" + s->in_elfv1_path;
	if (s->in_suppr_path && strcmp(s->in_suppr_path, ""))
	  in_suppression_path =
	    string(get_src_dir()) + "/tests/" + s->in_suppr_path;
	else
	  in_suppression_path.clear();

	abidiff_options = s->abidiff_options;
	ref_diff_report_path =
	  string(get_src_dir()) + "/tests/" + s->in_report_path;
	out_diff_report_path =
	  string(get_build_dir()) + "/tests/" + s->out_report_path;

	if (!ensure_parent_dir_created(out_diff_report_path))
	  {
	    cerr << "could not create parent directory for "
		 << out_diff_report_path;
	    is_ok = false;
	    continue;
	  }

	abidiff = string(get_build_dir()) + "/tools/abidiff";
	if (!abidiff_options.empty())
	  abidiff += " " + abidiff_options;

	if (!in_suppression_path.empty())
	  abidiff += " --suppressions " + in_suppression_path;

	cmd = abidiff + " " + in_elfv0_path + " " + in_elfv1_path;
	cmd += " > " + out_diff_report_path;

	bool abidiff_ok = true;
	int code = system(cmd.c_str());
	if (!WIFEXITED(code))
	  abidiff_ok = false;
	else
	  {
	    abigail::tools_utils::abidiff_status status =
	      static_cast<abidiff_status>(WEXITSTATUS(code));
	    if (status != s->status)
	      {
		cerr << "for command '"
		     << cmd
		     << "', expected abidiff status to be " << s->status
		     << " but instead, got " << status << "\n";
		abidiff_ok = false;
	      }
	  }

	if (abidiff_ok)
	  {
	    cmd = "diff -u " + ref_diff_report_path
	      + " " + out_diff_report_path;
	    if (system(cmd.c_str()))
	      is_ok = false;
	  }
	else
	  is_ok = false;
      }

    return !is_ok;
}
