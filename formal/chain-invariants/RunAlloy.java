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
 * For each command in the model:
 *   - a `check`: SAT => COUNTEREXAMPLE FOUND (property violated);
 *                UNSAT => no counterexample in scope (property holds in scope).
 *   - a `run`:   SAT => instance found (predicate satisfiable);
 *                UNSAT => no instance in scope.
 *
 * Exit code 2 if any `check` yields a counterexample (unexpected soundness failure).
 */
public class RunAlloy {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) { System.err.println("usage: RunAlloy <model.als>"); System.exit(1); }
        String file = args[0];
        A4Reporter rep = new A4Reporter();
        Module world = CompUtil.parseEverything_fromFile(rep, null, file);
        A4Options opts = new A4Options();
        opts.solver = kodkod.engine.satlab.SATFactory.DEFAULT; // pure-Java SAT4J, no native deps

        int checkViolations = 0;
        System.out.println("== Alloy run: " + file + " ==");
        for (Command cmd : world.getAllCommands()) {
            long t0 = System.currentTimeMillis();
            A4Solution ans = TranslateAlloyToKodkod.execute_command(rep, world.getAllReachableSigs(), cmd, opts);
            long ms = System.currentTimeMillis() - t0;
            boolean sat = ans.satisfiable();
            boolean isCheck = cmd.check;
            String verdict;
            if (isCheck) {
                verdict = sat ? "COUNTEREXAMPLE FOUND (property VIOLATED)"
                              : "no counterexample — property HOLDS in scope";
                if (sat) {
                    checkViolations++;
                    if (System.getenv("DUMP") != null) {
                        System.out.println("---- counterexample for " + cmd.label + " ----");
                        System.out.println(ans.toString());
                        System.out.println("---- end counterexample ----");
                    }
                }
            } else {
                verdict = sat ? "instance FOUND (satisfiable)"
                              : "no instance (UNSAT)";
            }
            System.out.printf("[%-5s] %-45s %-8s %s  (%d ms)%n",
                    isCheck ? "check" : "run", cmd.label, sat ? "SAT" : "UNSAT", verdict, ms);
        }
        System.out.println("== done: " + checkViolations + " check violation(s) ==");
        System.exit(checkViolations > 0 ? 2 : 0);
    }
}
