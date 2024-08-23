using AutoMapper;
using Connectify.Logger;
using Microsoft.AspNetCore.Identity;

namespace Connectify.Services
{
    public class ServiceManager : IServiceManager
    {
       
        private readonly Lazy<IAuthenticationService> _authenticationService;

        public ServiceManager( IMapper mapper, UserManager<IdentityUser> userManager, ILoggerManager logger, IConfiguration configuration)
        {
                _authenticationService = new Lazy<IAuthenticationService>(() => new AuthenticationService(mapper, userManager, logger, configuration));
        }

        public IAuthenticationService AuthenticationService => _authenticationService.Value;
    }
}
