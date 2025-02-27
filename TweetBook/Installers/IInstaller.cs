﻿using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace TweetBook.Installers
{
    public interface IInstaller
    {
        void InstallServices(IServiceCollection serviceCollection, IConfiguration configuration);
    }
}
