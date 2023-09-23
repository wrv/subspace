out\subdoc\subdoc -p out --out docs ^
    --include-file-pattern /sus/ ^
    --exclude-file-pattern /third_party/ ^
    --css subdoc-test-style.css ^
    --copy-file subdoc/gen_tests/subdoc-test-style.css ^
    --copy-file web/logo.png ^
    --favicon "logo.png;image/png" ^
    --project-md sus/project.md ^
    --project-logo logo.png ^
    --project-name Subspace ^
    --ignore-bad-code-links ^
    subspace/sus/num/uptr sus/boxed/box_ choice_unit
