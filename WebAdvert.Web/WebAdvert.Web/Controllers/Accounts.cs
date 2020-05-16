using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebAdvert.Web.Models.Accounts;

// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace WebAdvert.Web.Controllers
{
    public class Accounts : Controller
    {
        private readonly SignInManager<CognitoUser> m_SignInManager;
        private readonly UserManager<CognitoUser> m_UserManager;
        private readonly CognitoUserPool m_UserPool;
        public Accounts(SignInManager<CognitoUser> signInManager,UserManager<CognitoUser> userManager,CognitoUserPool pool)
        {
            m_SignInManager = signInManager;
            m_UserManager = userManager;
            m_UserPool = pool;
        }
        public async Task<IActionResult> SignUp()
        {
            var model = new SignupModel();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> SignUp(SignupModel model)
        {
            if(ModelState.IsValid)
            {
                var user = m_UserPool.GetUser(model.Email);
                if(user.Status !=null)
                {
                    ModelState.AddModelError("UserExists", "User with this email already exists");
                    return View(model);
                }

                user.Attributes.Add(CognitoAttribute.Name.ToString(), model.Email);
                var createdUser = await m_UserManager.CreateAsync(user, model.Password).ConfigureAwait(false);
                if(createdUser.Succeeded)
                {
                    RedirectToAction("Confirm");
                }
            }

            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Confirm(ConfirmModel model)
        {
            return View(model);
        }

        [HttpPost]
        [ActionName("Confirm")]
        public async Task<IActionResult> Confirm_Post(ConfirmModel model)
        {
            if(ModelState.IsValid)
            {
                var user = await m_UserManager.FindByEmailAsync(model.Email);
                if(user == null)
                {
                    ModelState.AddModelError("NotFound", "A user with a given email address not found");
                    return View(model);
                }

                var result = await m_UserManager.ConfirmEmailAsync(user, model.Code).ConfigureAwait(false);
                if(result.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    foreach(var item in result.Errors)
                    {
                        ModelState.AddModelError(item.Code, item.Description);
                    }
                    return View(model);
                }
            }
            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> Login(LoginModel model)
        {
            return View(model);
        }

        [HttpPost]
        [ActionName("Login")]
        public async Task<IActionResult> LoginPost(LoginModel model)
        {
            if(ModelState.IsValid)
            {
                var result = await m_SignInManager.PasswordSignInAsync(model.Email,
                    model.Password, model.RememberMe, false).ConfigureAwait(false);

                if(result.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError("LoginError", "Email and password do not match");
                }
            }
            return View("Login",model);
        }
    }
}
