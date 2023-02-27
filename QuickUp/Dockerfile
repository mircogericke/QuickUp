FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443
VOLUME /data
ENV QUICKUP_APPLICATIONSECRET=""
ENV QUICKUP_UPLOADSECRET=""

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src
COPY ["QuickUp/QuickUp.csproj", "QuickUp/"]
RUN dotnet restore "QuickUp/QuickUp.csproj"
COPY . .
WORKDIR "/src/QuickUp"
RUN dotnet build "QuickUp.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "QuickUp.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "QuickUp.dll"]