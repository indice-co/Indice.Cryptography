﻿using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using Indice.Oba.Host.Swagger;
using Indice.Psd2.Cryptography.Tokens.HttpMessageSigning;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.OpenApi.Models;

namespace Indice.Oba.Host;

public class Startup
{
    public Startup(IConfiguration configuration, IWebHostEnvironment env) {
        Configuration = configuration;
        Environment = env;
    }

    public IConfiguration Configuration { get; }
    public IWebHostEnvironment Environment { get; }

    // This method gets called by the runtime. Use this method to add services to the container.
    public void ConfigureServices(IServiceCollection services) {
        services.AddControllersWithViews()
                .AddCertificateEndpoints(x => {
                    x.IssuerDomain = Configuration["Certificates:Issuer"];
                    x.AddEntityFrameworkStore(options => {
                        options.ConfigureDbContext = builder => {
                            builder.UseSqlServer(Configuration.GetConnectionString("CertificatesDb"));
                        };
                    });
                });
        services.AddSwaggerGen(x => {
            x.SchemaFilter<SchemaExamplesFilter>();
            x.SwaggerDoc("cert", new OpenApiInfo {
                Description = "Certificate *utilities*",
                Title = "Certificate",
                Version = "v1"
            });
            var xmlFiles = new[] {
                $"{Assembly.GetEntryAssembly().GetName().Name}.xml",
                "Indice.Oba.AspNetCore.xml",
                "Indice.Psd2.Cryptography.xml"
            };
            foreach (var xmlFile in xmlFiles) {
                var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                if (File.Exists(xmlPath)) {
                    x.IncludeXmlComments(xmlPath);
                }
            }
        });
        var httpSignatureCertificate = new X509Certificate2(Path.Combine(Environment.ContentRootPath, Configuration["HttpSignatures:PfxName"]), Configuration["HttpSignatures:PfxPass"], X509KeyStorageFlags.MachineKeySet);
        services.AddHttpSignatures(options => {
            options.MapPath("/payments", HeaderFieldNames.RequestTarget, HeaderFieldNames.Created, HttpDigest.HTTPHeaderName, "x-response-id");
            options.MapPath("/payments/execute", HeaderFieldNames.RequestTarget, HeaderFieldNames.Created, HttpDigest.HTTPHeaderName, "x-response-id");
        })
        .AddSigningCredential(httpSignatureCertificate);
    }

    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env) {
        if (env.IsDevelopment()) {
            app.UseDeveloperExceptionPage();
        } else {
            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            app.UseHsts();
        }
        app.UseHttpsRedirection();
        app.UseRouting();
        app.UseHttpSignatures();
        app.UseSwagger();
        app.UseSwaggerUI(x => {
            x.RoutePrefix = "swagger/ui";
            x.SwaggerEndpoint($"/swagger/cert/swagger.json", "cert");
        });
        app.UseEndpoints(endpoints => {
            endpoints.MapControllers();
        });
    }
}
