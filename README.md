# MUD

Lightweight mud manager that converts the mud acls into open flow rules.

Steps:

1. Clone the repo

2. install requirements.txt

3. change the dir_input in mud_manager/mud_controller.py

4. run the mud server
    cd mudserver
    python3 mudserver.py

5. run the mud manager
6. 
   Below commands will test if mud_controller.py script downloading MUD file from mudserver.

   cd mud_manager
   
   python mud_controller.py [MUD_URI/NULL] [R/W/U]
   
   W -> Get the mud file and signature file from mud uri and verify the signature and store the MUD file.
   python mud_controller.py http://<muduri>/mud/device1.json W
   
   example(in given code): python3 mud_controller.py http://127.0.0.1:8080/mud/mudfile.json W
   

   R1 -> For INGRESS

   example: python mud_controller.py null R1

   R2 -> For EGRESS

   example: python mud_controller.py null R2

   U1 -> For INGRESS ACE Name

   example: python mud_controller.py null U1

   U2 -> For EGRESS ACE Name 

   example: python mud_controller.py null U2

  
