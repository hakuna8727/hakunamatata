!DOCTYPE html>
<html>
<head>
    <title>student Feedback</title>
<style>
        body {
            font-family:"times new roman";
            background-color: lightyellow;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 400vh;
            margin: 0;
        }
.container {
            width: 300px;
            padding: 20px;
	    background-color: pink;
            border: 5px solid #aaa;
            border-radius: 50px;
            box-shadow: 2px 2px 12px rgba(20,5,63,1.0);
            margin: auto;
            text-align: center;
        }
</style>
</head>
<body>
<div class="container">
    <form action="submit_form.php" method="post">
	<h1 align="center">Feedback Form For Students</h1>
        <label for="name">Name:</label>
        <input type="text" id="name" name="name" required><br><br>
        
        <label for="Branch">Branch:</label>
        <input type="Branch" id="Branch" name="Branch" required><br><br>

	<label>Year:</label>
        <input type="radio" id="1st" name="Year" value="1st" required>
        <label for="1st">1st</label>
        <input type="radio" id="2nd" name="Year" value="2nd" required>
        <label for="2nd">2nd</label>
 	<input type="radio" id="3rd" name="Year" value="3rd" required>
        <label for="3rd">3rd</label><br><br>

                
        <label for="subject">Subject:</label>
        <select id="subject" name="subject" required>
            <option value="">Select subject</option>
            <option value="human values">human values</option>
            <option value="Fundamental of computer and It">Fundamental of computer and It</option>
            <option value="Mathematics">Mathematics</option>
            <option value="Problem solving using c">Problem solving using c</option>
		<option value="English">English</option>	
		<option value="Fundamental of statistics">Fundamental of statistics</option>
<option value="Computer system architecture">Computer system architecture</option>
<option value="Enviornmental studies">Enviornmental studies</option>
<option value="Computer networks">Computer networks</option>
<option value="Programming in python ">Programming in python </option>
<option value="Data structure">Data structure</option>
<option value="web Designing">web Designing</option>
        </select><br><br>
        <label>satisfaction:</label>
        <input type="radio" id="satisfied" name="satisfaction" value="satisfied" required>
        <label for="satisfied">satisfied</label>
        <input type="radio" id=" not satisfied" name="satisfaction" value="not satisfied" required>
        <label for="not satisfied">not satisfied</label><br><br>
        <input type="submit" value="Submit">
	<input type="reset" value="Reset">
    </form>
</body>
</html>
