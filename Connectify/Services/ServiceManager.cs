using AutoMapper;

using Microsoft.AspNetCore.Identity;

namespace Connectify.Services
{
    public class ServiceManager : IServiceManager
    {
       
        private readonly Lazy<IAuthenticationService> _authenticationService;

        public ServiceManager( IMapper mapper, UserManager<IdentityUser> userManager)
        {
                _authenticationService = new Lazy<IAuthenticationService>(() => new AuthenticationService(mapper, userManager));
        }

        public IAuthenticationService AuthenticationService => _authenticationService.Value;
    }
}
