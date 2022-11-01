using JarvisWebRRHH.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace JarvisWebRRHH.Controllers
{
    public class LoginController : Controller
    {
        [HttpPost("/account/login")]
        public async Task<IActionResult> Login(UserCredentials credentials)
        {
            //Indicamos el dominio en el que vamos a buscar al usuario
            //GAMMA/DC=ZHMSEGUROS,DC=local
            //string path = "LDAP://servidor.dominio.local/dc=servidor,dc=dominio,dc=local";
            //string path = "LDAP://gamma.zhmseguros.local/dc=GAMMA,dc=ZHMSEGUROS,dc=local";
            string path = "LDAP://Gamma/DC=ZHMSEGUROS,DC=local";

            try
            {
                using (DirectoryEntry entry = new DirectoryEntry(path, credentials.Username, credentials.Password))
                {
                    using (DirectorySearcher searcher = new DirectorySearcher(entry))
                    {
                        //Buscamos por la propiedad SamAccountName
                        searcher.Filter = "(samaccountname=" + credentials.Username + ")";
                        //Buscamos el usuario con la cuenta indicada
                        SearchResult result = searcher.FindOne();
                        if (result != null)
                        {
                            string role = "";
                            //Comporbamos las propiedades del usuario
                            ResultPropertyCollection fields = result.Properties;
                            foreach (String ldapField in fields.PropertyNames)
                            {
                                foreach (Object myCollection in fields[ldapField])
                                {
                                    if (ldapField == "employeetype")
                                        role = myCollection.ToString().ToLower();
                                }
                            }

                            //Añadimos los claims Usuario y Rol para tenerlos disponibles en la Cookie
                            //Podríamos obtenerlos de una base de datos.
                            var claims = new[]
                            {
                                new Claim(ClaimTypes.Name, credentials.Username),
                                new Claim(ClaimTypes.Role, role)
                            };

                            //Creamos el principal
                            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

                            //Generamos la cookie. SignInAsync es un método de extensión del contexto.
                            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, claimsPrincipal);

                            //Redirigimos a la Home
                            return LocalRedirect("/");

                        }
                        else
                            return LocalRedirect("/login/Invalid credentials");
                    }
                }

            }
            catch (Exception ex)
            {
                return LocalRedirect("/login/Invalid credentials");
            }
        }

        [HttpGet("/account/logout")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return LocalRedirect("/");
        }
    }
}
