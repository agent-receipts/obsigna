import edu.mit.csail.sdg.alloy4.A4Reporter;
import edu.mit.csail.sdg.ast.Command;
import edu.mit.csail.sdg.ast.Module;
import edu.mit.csail.sdg.parser.CompUtil;
import edu.mit.csail.sdg.translator.A4Options;
import edu.mit.csail.sdg.translator.A4Solution;
import edu.mit.csail.sdg.translator.TranslateAlloyToKodkod;

/**
 * Headless Alloy 6 command runner.
 *
 * Every command in the model carries an `expect` annotation:
 *   - `check ... expect 0` — expect UNSAT (no counterexample → property holds in scope).
 *   - `run ...   expect 1` — expect SAT   (an instance exists → scenario reachable,
 *                                           i.e. the paired check is NON-vacuous).
 *
 * A result that CONTRADICTS the command's `expect` is an "unexpected" outcome and
 * makes this runner exit non-zero. This matters for BOTH directions:
 *   - a `check` that comes back SAT is a real counterexample (property violated);
 *   - a `run` that comes back UNSAT means a scenario the model relies on for
 *     non-vacuity became unreachable — which would silently turn a paired `check`
 *     into a vacuous pass. Enforcing the `expect` on runs closes that hole.
 *
 * Exit codes:
 *   0  every command matched its `expect`
 *   2  at least one command's result contradicted its `expect`
 *   3  a command threw during translation/solving (partial run)
 *   1  usage error
 *
 * Set DUMP=1 to print the instance for any unexpected result.
 */
public class RunAlloy {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) { System.err.println("usage: RunAlloy <model.als>"); System.exit(1); }
        String file = args[0];
        A4Reporter rep = new A4Reporter();
        Module world = CompUtil.parseEverything_fromFile(rep, null, file);
        A4Options opts = new A4Options();
        opts.solver = kodkod.engine.satlab.SATFactory.DEFAULT; // pure-Java SAT4J, no native deps

        boolean dump = System.getenv("DUMP") != null;
        int unexpected = 0;   // results that contradict the command's `expect`
        int errored = 0;      // commands that threw
        System.out.println("== Alloy run: " + file + " ==");
        for (Command cmd : world.getAllCommands()) {
            long t0 = System.currentTimeMillis();
            boolean sat;
            A4Solution ans;
            try {
                ans = TranslateAlloyToKodkod.execute_command(rep, world.getAllReachableSigs(), cmd, opts);
                sat = ans.satisfiable();
            } catch (Throwable t) {
                // Isolate per-command failures so one blow-up cannot silently skip the
                // rest of the suite or downgrade a later counterexample's exit signal.
                errored++;
                System.out.printf("[%-5s] %-45s %-8s ERROR: %s%n",
                        cmd.check ? "check" : "run", cmd.label, "ERR", t);
                continue;
            }
            long ms = System.currentTimeMillis() - t0;

            // cmd.expects: 1 => expect SAT, 0 => expect UNSAT, -1 => unspecified.
            int expects = cmd.expects;
            boolean matched;
            if (expects == 1)      matched = sat;
            else if (expects == 0) matched = !sat;
            else                   matched = !(cmd.check && sat); // no annotation: only a check→SAT is "bad"

            String meaning;
            if (cmd.check) {
                meaning = sat ? "COUNTEREXAMPLE FOUND (property VIOLATED)"
                              : "no counterexample — property HOLDS in scope";
            } else {
                meaning = sat ? "instance FOUND (scenario reachable)"
                              : "no instance (UNSAT — scenario UNREACHABLE)";
            }
            String tag = matched ? "" : "  <<< UNEXPECTED (expect "
                    + (expects == 1 ? "SAT" : expects == 0 ? "UNSAT" : "?") + ")";
            if (!matched) {
                unexpected++;
                if (dump) {
                    System.out.println("---- instance for " + cmd.label + " ----");
                    System.out.println(ans.toString());
                    System.out.println("---- end instance ----");
                }
            }
            System.out.printf("[%-5s] %-45s %-8s %s  (%d ms)%s%n",
                    cmd.check ? "check" : "run", cmd.label, sat ? "SAT" : "UNSAT", meaning, ms, tag);
        }
        System.out.println("== done: " + unexpected + " unexpected result(s), " + errored + " error(s) ==");
        System.exit(errored > 0 ? 3 : unexpected > 0 ? 2 : 0);
    }
}
