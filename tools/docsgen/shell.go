package main

import (
	"fmt"
	"html"
)

// shell wraps rendered page content in the same chrome (fonts, palette, nav,
// footer) as docs/index.html so generated pages match the landing page.
// title is plain text; content is trusted HTML.
func shell(title, content string) string {
	title = html.EscapeString(title)
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<link rel="icon" type="image/png" sizes="64x64" href="favicon.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Quicksand:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root{
    --teal:#3FA39B; --teal-dark:#2E7D78; --teal-deep:#1f5b57; --teal-light:#8FCEC8; --teal-bg:#E8F5F2;
    --coral:#EC8B77; --coral-deep:#d97560;
    --cream:#FBF8F1; --paper:#fff;
    --ink:#273a38; --muted:#6a8682;
    --radius:22px; --shadow:0 16px 40px -18px rgba(31,91,87,.35);
  }
  *{box-sizing:border-box}
  html{scroll-behavior:smooth}
  body{
    margin:0; font-family:Quicksand,system-ui,sans-serif; color:var(--ink);
    background:var(--cream);
    background-image:radial-gradient(1100px 520px at 50%% -240px, var(--teal-bg), transparent 70%%);
    line-height:1.6; -webkit-font-smoothing:antialiased;
  }
  a{color:var(--teal-dark); text-decoration:none}
  .wrap{max-width:980px; margin:0 auto; padding:0 22px}
  code,pre{font-family:"JetBrains Mono",ui-monospace,monospace}

  nav{display:flex; align-items:center; justify-content:space-between; padding:20px 22px; max-width:980px; margin:0 auto}
  nav .brand{display:flex; align-items:center; gap:10px; font-weight:700; font-size:1.15rem; color:var(--teal-deep)}
  nav .brand img{width:34px;height:34px}
  nav .links{display:flex; gap:22px; font-weight:600}
  nav .links a{color:var(--muted)}
  nav .links a:hover{color:var(--teal-dark)}

  .eyebrow{text-transform:uppercase; letter-spacing:2px; font-size:.78rem; font-weight:700; color:var(--teal); margin-bottom:4px}

  /* docs catalog hero */
  .doc-hero{text-align:center; padding:30px 0 6px}
  .doc-hero h1{font-size:2.8rem; margin:.1em 0 .1em; color:var(--teal-deep); letter-spacing:-.5px}
  .doc-hero .eyebrow{text-align:center}
  .doc-hero .tagline{font-size:1.15rem; font-weight:500; color:var(--muted); max-width:44ch; margin:.2em auto}
  .grid{display:grid; grid-template-columns:repeat(2,1fr); gap:18px; padding:14px 0 8px}
  .card{background:var(--paper); border-radius:var(--radius); padding:22px 22px 20px; box-shadow:var(--shadow); border-top:4px solid var(--teal); display:block; transition:transform .15s}
  .card:hover{transform:translateY(-3px)}
  .card:nth-child(even){border-top-color:var(--coral)}
  .card h3{margin:0 0 .3em; font-size:1.18rem; color:var(--teal-deep)}
  .card p{margin:0; color:var(--muted); font-size:.95rem}

  /* rendered markdown */
  .doc{max-width:840px; margin:0 auto; padding:10px 22px 20px}
  .doc .backlink{display:inline-block; margin:6px 0 14px; font-weight:600; color:var(--muted)}
  .doc .backlink:hover{color:var(--teal-dark)}
  .doc article{background:var(--paper); border-radius:var(--radius); padding:32px 40px; box-shadow:var(--shadow); border-top:4px solid var(--teal)}
  .doc h1{font-size:2.2rem; color:var(--teal-deep); margin:.1em 0 .5em; letter-spacing:-.4px}
  .doc h2{font-size:1.5rem; color:var(--teal-deep); margin:1.5em 0 .5em; border-bottom:2px solid var(--teal-bg); padding-bottom:.22em}
  .doc h3{font-size:1.2rem; color:var(--teal-dark); margin:1.3em 0 .4em}
  .doc h4{font-size:1.02rem; color:var(--teal-dark); margin:1.2em 0 .3em}
  .doc p{margin:.65em 0}
  .doc a{color:var(--teal-dark); font-weight:600}
  .doc a:hover{text-decoration:underline}
  .doc ul,.doc ol{padding-left:1.4em; margin:.6em 0}
  .doc li{margin:.3em 0}
  .doc code{background:var(--teal-bg); color:var(--teal-dark); padding:1px 6px; border-radius:6px; font-size:.86em}
  .doc pre{background:#22403d; color:#e7f4f1; border-radius:13px; padding:16px 18px; overflow-x:auto; line-height:1.6; margin:1em 0}
  .doc pre code{background:none; color:inherit; padding:0; font-size:.86rem}
  .doc blockquote{margin:.9em 0; padding:.5em 1em; border-left:4px solid var(--coral); background:#fff6f3; color:var(--muted); border-radius:0 10px 10px 0}
  .doc table{border-collapse:collapse; width:100%%; margin:1.1em 0; font-size:.9rem; display:block; overflow-x:auto}
  .doc th,.doc td{border:1px solid #dceae7; padding:8px 11px; text-align:left; vertical-align:top}
  .doc th{background:var(--teal-bg); color:var(--teal-deep); white-space:nowrap}
  .doc tr:nth-child(even) td{background:#fbfdfc}
  .doc hr{border:0; border-top:2px solid var(--teal-bg); margin:1.7em 0}

  footer{text-align:center; color:var(--muted); padding:40px 0 50px; font-size:.95rem}
  footer a{font-weight:600}
  footer .heart{color:var(--coral)}

  @media (max-width:720px){
    .grid{grid-template-columns:1fr}
    .doc article{padding:24px 22px}
    nav .links{display:none}
  }
</style>
</head>
<body>

<nav>
  <a class="brand" href="index.html"><img src="arca-light.png" alt="">arca</a>
  <span class="links">
    <a href="index.html#features">Features</a>
    <a href="index.html#install">Install</a>
    <a href="docs.html">Docs</a>
    <a href="https://github.com/arenzana/arca">GitHub ↗</a>
  </span>
</nav>

%s

<footer>
  Made with <span class="heart">♥</span> and <a href="https://github.com/FiloSottile/age">age</a> ·
  <a href="index.html">Home</a> ·
  <a href="https://github.com/arenzana/arca">GitHub</a> ·
  <a href="https://github.com/arenzana/arca/blob/main/SECURITY.md">Security</a>
</footer>

</body>
</html>
`, title, content)
}
