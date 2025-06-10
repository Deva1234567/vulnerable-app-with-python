<?php
 $servername = "localhost";  
 $username = "root";  
 $password = "examplePW";
  $dbname = "volunteers";  
 $conn = new mysqli($servername, $username, $password, $dbname);  
 
 $conn=new mysqli('localhost','root','','test1');
 if($conn->connect_error){
    die('Connection Failed: '.$conn->connect_error);
 }echo "Connected Successfully .<br>";
   $Registration=$_POST['Registration'];
 $Student=$_POST['Student'];
 $Mobile=$_POST['Mobile'];
 $Category=$_POST['Category'];
 $Rank=$_POST['Rank'];
 
 $sql = "INSERT INTO test1(firstName, lastName, age, phoneNUmber, email, reason) VALUES" . "('$firstName', '$lastName', '$age', '$phoneNumber', '$email', '$reason')";
 echo "Running SQL statement - <br>" . $sql . "<br>";

 if($conn->query($sql) == TRUE)
 {
     echo "Request Sent <br>";
 }
 else{
     echo "Error: " . $sql . "<br>" . $conn->error;
 }

 ?>