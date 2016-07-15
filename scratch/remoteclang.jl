using Cxx
include(Pkg.dir("Cxx","test","llvmincludes.jl"))
cxx"""
#include "llvm/Option/Option.h"
#include "clang/Tooling/JSONCompilationDatabase.h"
#include "clang/Driver/Compilation.h"
#include "clang/Driver/Driver.h"
#include "clang/Driver/Job.h"
#include "clang/Driver/Tool.h"
#include "clang/Basic/DiagnosticIDs.h"
#include "clang/Basic/DiagnosticOptions.h"
#include "clang/Frontend/TextDiagnosticPrinter.h"
#include "clang/Frontend/FrontendDiagnostic.h"
using namespace llvm;
using namespace llvm::opt;
using namespace clang;
using namespace clang::tooling;


/// \brief Retrieves the clang CC1 specific flags out of the compilation's jobs.
///
/// Returns NULL on error.
static const llvm::opt::ArgStringList *getCC1Arguments(
    clang::DiagnosticsEngine *Diagnostics,
    clang::driver::Compilation *Compilation) {
  // We expect to get back exactly one Command job, if we didn't something
  // failed. Extract that job from the Compilation.
  const clang::driver::JobList &Jobs = Compilation->getJobs();
  if (Jobs.size() != 1 || !isa<clang::driver::Command>(*Jobs.begin())) {
    SmallString<256> error_msg;
    llvm::raw_svector_ostream error_stream(error_msg);
    Jobs.Print(error_stream, "; ", true);
    Diagnostics->Report(clang::diag::err_fe_expected_compiler_job)
        << error_stream.str();
    return nullptr;
  }

  // The one job we find should be to invoke clang again.
  const clang::driver::Command &Cmd =
      cast<clang::driver::Command>(*Jobs.begin());
  if (StringRef(Cmd.getCreator().getName()) != "clang") {
    Diagnostics->Report(clang::diag::err_fe_expected_clang_command);
    return nullptr;
  }

  return &Cmd.getArguments();
}

/// \brief Returns a clang build invocation initialized from the CC1 flags.
clang::CompilerInvocation *newInvocation(
    clang::DiagnosticsEngine *Diagnostics,
    const llvm::opt::ArgStringList &CC1Args) {
  assert(!CC1Args.empty() && "Must at least contain the program name!");
  clang::CompilerInvocation *Invocation = new clang::CompilerInvocation;
  clang::CompilerInvocation::CreateFromArgs(
      *Invocation, CC1Args.data() + 1, CC1Args.data() + CC1Args.size(),
      *Diagnostics);
  Invocation->getFrontendOpts().DisableFree = false;
  Invocation->getCodeGenOpts().DisableFree = false;
  Invocation->getDependencyOutputOpts() = DependencyOutputOptions();
  return Invocation;
}
"""
invocation = icxx"""
std::string error;
auto cdb = clang::tooling::JSONCompilationDatabase::loadFromFile("/home/kfischer/julia/compile_commands.json", error);
CompilerInvocation Inv;
std::vector<const char*> Argv;
CompileCommand TheCommand = cdb->getCompileCommands("/home/kfischer/julia/src/gf.c")[0];
for (const std::string &Str : TheCommand.CommandLine)
  Argv.push_back(Str.c_str());
const char *const BinaryName = Argv[0];
IntrusiveRefCntPtr<DiagnosticOptions> DiagOpts = new DiagnosticOptions();
TextDiagnosticPrinter DiagnosticPrinter(
    llvm::errs(), &*DiagOpts);
DiagnosticsEngine Diagnostics(
    IntrusiveRefCntPtr<clang::DiagnosticIDs>(new DiagnosticIDs()), &*DiagOpts,
    &DiagnosticPrinter, false);

const std::unique_ptr<clang::driver::Driver> Driver(new clang::driver::Driver(
    BinaryName, llvm::sys::getDefaultTargetTriple(), Diagnostics));
// Since the input might only be virtual, don't check whether it exists.
Driver->setCheckInputsExist(false);
const std::unique_ptr<clang::driver::Compilation> Compilation(
    Driver->BuildCompilation(llvm::makeArrayRef(Argv)));
const llvm::opt::ArgStringList *const CC1Args = getCC1Arguments(
    &Diagnostics, Compilation.get());
if (!CC1Args) {
  assert(false);
}
return newInvocation(&Diagnostics, *CC1Args);
"""

RemoteClang = Cxx.setup_instance_from_inovcation(invocation);
Cxx.initialize_instance!(RemoteClang; register_boot = false)
push!(Cxx.active_instances, RemoteClang)
RemoteClang = Cxx.CxxInstance{length(Cxx.active_instances)}()

nothing
