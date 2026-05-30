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

<p>

  <ol>
    <li>Initialization</li>
    <p>Provide a file containing URLs to test. The script creates a Scanner for each URL.It builds a massive "Payload List" by combining:Standard paths (/etc/passwd).Double-encoded paths (to bypass filters).Paths with null bytes (%00.jpg).</p>

<li>Authentication Check</li>
<p>The script visits the URL once to check if it works.Smart Check: If the page contains words like "login" or "password", the script PAUSES.It asks you to paste a PHPSESSID cookie.It saves this cookie so it can scan the "logged in" part of the site.</p>

<li>The Scanning Loop</li>
<p>It looks at the URL (e.g., site.com?page=index&view=home).It isolates one parameter at a time (e.g., starts with page).Baseline: It sends a safe request (page=test123) to see what the normal response looks like (length and content).</p>

<li>The Exploitation Loop</li>
<p>It starts replacing the parameter value with the Payload List.Example: It tries page=../../../etc/passwd.It waits for the server response.</p>

<li>Detection & Reporting</li>
<p>It compares the malicious response to the Baseline.
  
  Success Criteria: Does the response contain root: or daemon:? (Found /etc/passwd) Is the response way bigger than normal?
  
  If YES: It prints the success message and saves the data to a text file, then moves to the next URL.
  
  If NO: It tries the next payload in the list.
</p>
</ol>
Workflow Diagram:
</p>
