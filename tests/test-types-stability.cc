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

// Author: Dodji Seketeli

/// @file
///
/// This program tests that the representation of types by the
/// internal representation of libabigail is stable through reading
/// from ELF/DWARF, constructing an internal represenation, saving that
/// internal presentation to the abixml format, reading from that
/// abixml format and constructing an internal representation from it
/// again.
///
/// This program thus compares the internal representation that is
/// built from reading from ELF/DWARF and the one that is built from
/// the abixml (which itself results from the serialization of the
/// first internal representation to abixml).
///
/// The comparison is expected to yield the empty set.

#include <string>
#include <fstream>
#include <iostream>
#include <cstdlib>
#include "abg-tools-utils.h"
#include "test-utils.h"
#include "abg-dwarf-reader.h"
#include "abg-comparison.h"
#include "abg-workers.h"

using std::string;
using std::ofstream;
using std::cerr;

// A set of elf files to test type stability for.
const char* elf_paths[] =
{
  "data/test-types-stability/pr19434-elf0",
  "data/test-types-stability/pr19139-DomainNeighborMapInst.o",
  "data/test-types-stability/pr19202-libmpi_gpfs.so.5.0",
  "data/test-types-stability/pr19026-libvtkIOSQL-6.1.so.1",
  "data/test-types-stability/pr19138-elf0",
  "data/test-types-stability/pr19433-custom0",
  "data/test-types-stability/pr19141-get5d.o",
  "data/test-types-stability/pr19142-topo.o",
  "data/test-types-stability/pr19204-libtcmalloc.so.4.2.6-xlc",
  // The below should always be the last element of array.
  0
};

/// A task which launches abidw --abidiff on a binary
/// passed to the constructor of the task.
struct test_task : public abigail::workers::task
{
  const string path;
  const bool no_default_sizes;
  string error_message;
  bool is_ok;

  /// The constructor of the test task.
  ///
  /// @param elf_path the path to the elf binary on which we are
  /// supposed to launch abidw --abidiff.
  test_task(const string& elf_path, bool no_default_sizes)
    : path(elf_path),
      no_default_sizes(no_default_sizes),
      is_ok(true)
  {}

  /// This virtual function overload actually performs the job of the task.
  ///
  /// It calls abidw --abidiff on the binary refered to by the task.
  /// It thus stores a flag saying if the result of abidw --abidiff is
  /// OK or not.
  virtual void
  perform()
  {
    using abigail::tests::get_src_dir;
    using abigail::tests::get_build_dir;

    string abidw = string(get_build_dir()) + "/tools/abidw";
    string elf_path = string(get_src_dir()) + "/tests/" + path;
    string cmd = abidw + " --abidiff "
		 + (no_default_sizes ? "--no-write-default-sizes " : "")
		 + elf_path;
    if (system(cmd.c_str()))
      {
	error_message =
	    "IR stability issue detected for binary " + elf_path
	    + (no_default_sizes ? " with --no-write-default-sizes" : "");
	is_ok = false;
      }
  }
}; // end struct test_task

/// A convenience typedef for a shared_ptr to @ref test_task.
typedef shared_ptr<test_task> test_task_sptr;

int
main()
{
  using std::vector;
  using abg_compat::dynamic_pointer_cast;
  using abigail::workers::queue;
  using abigail::workers::task;
  using abigail::workers::task_sptr;
  using abigail::workers::get_number_of_threads;

  /// Create a task queue.  The max number of worker threads of the
  /// queue is the number of the concurrent threads supported by the
  /// processor of the machine this code runs on.
  const size_t num_tests = (sizeof(elf_paths) / sizeof(char*) - 1) * 2;
  size_t num_workers = std::min(get_number_of_threads(), num_tests);
  queue task_queue(num_workers);

  /// Create one task per binary registered for this test, and push
  /// them to the task queue.  Pushing a task to the queue triggers
  /// a worker thread that starts working on the task.
  for (const char** p = elf_paths; p && *p; ++p)
    {
      test_task_sptr t(new test_task(*p, false));
      ABG_ASSERT(task_queue.schedule_task(t));

      t.reset(new test_task(*p, true));
      ABG_ASSERT(task_queue.schedule_task(t));
    }

  /// Wait for all worker threads to finish their job, and wind down.
  task_queue.wait_for_workers_to_complete();

  // Now walk the results and print whatever error messages need to be
  // printed.

  const vector<task_sptr>& completed_tasks =
    task_queue.get_completed_tasks();

  ABG_ASSERT(completed_tasks.size () == num_tests);

  bool is_ok = true;
  for (vector<task_sptr>::const_iterator ti = completed_tasks.begin();
       ti != completed_tasks.end();
       ++ti)
    {
      test_task_sptr t = dynamic_pointer_cast<test_task>(*ti);
      if (!t->is_ok)
	{
	  is_ok = false;
	  cerr << t->error_message << "\n";
	}
    }

  return !is_ok;
}
