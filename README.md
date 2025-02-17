<!DOCTYPE html>
<html>
<head>
    <title>Simple Form</title>
<style>
        body {
            font-family:times new roman;
            background-color: lightgray;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
.container {
            width: 300px;
            padding: 20px;
	    background-color: white;
            border: 5px solid #aaa;
            border-radius: 10px;
            box-shadow: 2px 2px 12px rgba(20,5,63,1.0);
            margin: auto;
            text-align: center;
        }
</style>
</head>
<body>
<div class="container">
    <form action="submit_form.php" method="post">
	<h1 align="center";> Form By Hakam Singh </h1>
        <label for="name">Name:</label>
        <input type="text" id="name" name="name" required><br><br>
        
        <label for="email">Email:</label>
        <input type="email" id="email" name="email" required><br><br>

	<label for="Password">Password:</label>
        <input type="Password" id="Password" name="Password" required><br><br>
                
        <label for="country">Country:</label>
        <select id="country" name="country" required>
            <option value="">Select Country</option>
            <option value="USA">USA</option>
            <option value="UK">UK</option>
            <option value="Canada">Canada</option>
            <option value="Australia">Australia</option>
		<option value="India">India</option>	
		<option value="Russia">Russia</option>
        </select><br><br>
        <label>Gender:</label>
        <input type="radio" id="male" name="gender" value="male" required>
        <label for="male">Male</label>
        <input type="radio" id="female" name="gender" value="female" required>
        <label for="female">Female</label><br><br>
        <input type="submit" value="Submit">
	<input type="reset" value="Reset">
    </form>
</body>
</html>
