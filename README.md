<h1>Path Traversal Detection Agent</h1>
<img src="https://cdn.prod.website-files.com/642adcaf364024654c71df23/67435e0828800ec7fbb3be3f_blog-visuals-path-traversal-attack_7db5a8434c983ca6f7c83f310fecbf1c_2000.jpeg" height=450px width=1000px >
<h3>What is Path Traversal Vulnerability? </h3>
<p>A path traversal attack (also known as <b>Directory Traversal</b>) aims to access files and directories that are stored outside the web root folder. By manipulating variables that reference files with “dot-dot-slash (../)” sequences and its variations or by using absolute file paths, it may be possible to access arbitrary files and directories stored on file system including application source code or configuration and critical system files.</p>
<p><b>This attack is also known as “dot-dot-slash”, “directory traversal”, “directory climbing” and “backtracking”.</b></p>
<p>
  <h4>A variety of payloads can be used:</h4>
<ol>
  <li>Encoding and double encoding:</li>
  <ul>
    <li>%2e%2e%2f represents ../</li>
    <li>%2e%2e/ represents ../</li>
    <li>..%2f represents ../ and so on...</li>
  </ul>
  <li>Percent encoding (aka URL encoding)</li>
  <ul>
    <li>..%c0%af represents ../ </li>
    <li>..%c1%9c represents ..\</li>
  </ul>
</ol>

</p>
<h3>What this agent does</h3>
<img src="https://github.com/user-attachments/assets/de9f694b-e108-4262-848f-30cd763dc02b" >
<p></p>
