# Standard Imports
import json
import logging
import re
from collections import namedtuple
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, cast

import discord
from discord.errors import Forbidden

# Redbot Imports
from redbot.core import Config, checks, commands
from thefuzz import process

__version__ = "1.1.0"
__author__ = "oranges"

log = logging.getLogger("red.oranges_rolemanage")

BaseCog = getattr(commands, "Cog", object)


class RoleManage(BaseCog):
    """
    Role manager module
    """

    def __init__(self, bot):
        self.bot = bot
        self.rolemanages_by_role = {}
        self.config = Config.get_conf(
            self, identifier=672261474290237490, force_registration=True
        )
        self.visible_config = [
            "enabled",
            "role_map",
            "logging_channel",
            "rolemanages",
            "member_role_id",
            "punished_role_id",
        ]

        default_guild = {
            "enabled": True,
            "role_map": {},
            "logging_channel": False,
            "member_role_id": None,
            "punished_role_id": None,
        }

        self.config.register_guild(**default_guild)

    @commands.guild_only()
    @commands.group()
    @checks.mod_or_permissions(administrator=True)
    async def rolemanage(self, ctx):
        """
        rolemanage module
        """
        pass

    @commands.guild_only()
    @rolemanage.group()
    @checks.mod_or_permissions(administrator=True)
    async def config(self, ctx):
        """
        Configure the rolemanage module
        """
        pass

    @config.command()
    async def current(self, ctx):
        """
        Gets the current settings for the verification system
        """
        settings = await self.config.guild(ctx.guild).all()
        embed: discord.Embed = discord.Embed(title="__Current settings:__")
        for k, v in settings.items():
            # Hide any non-whitelisted config settings (safety moment)
            if k in self.visible_config:
                if v == "":
                    v = None
                embed.add_field(name=f"{k}:", value=v, inline=False)
            else:
                embed.add_field(name=f"{k}:", value="`redacted`", inline=False)
        await ctx.send(embed=embed)

    @config.command()
    async def set_log_channel(self, ctx, channel: discord.TextChannel):
        """
        Set the channel that the rolemanages are logged to
        """
        try:
            await self.config.guild(ctx.guild).logging_channel.set(channel.id)
            await ctx.send(f"Channel set to {channel}")
        except (ValueError, KeyError, AttributeError) as e:
            await ctx.send("There was a problem setting the channel to log to")
            raise e

    async def send_log_message(
        self,
        guild: discord.Guild,
        message: str,
        source: discord.Member,
        target: discord.Member,
        jump_url: str,
    ):
        """
        Send a log message about a rolemanage action happening
        """
        channel: discord.TextChannel = await self.get_log_channel(guild)
        if channel:
            embed = discord.Embed(url=jump_url, title="__rolemanage action:__")
            embed.add_field(name="Source", value=source, inline=False)
            embed.add_field(name="Target", value=target, inline=False)
            embed.add_field(name="Action", value=message, inline=False)
            await channel.send(embed=embed)

    async def get_log_channel(self, guild: discord.Guild):
        """
        Get the configured channel for this guild, or None if none is set or the channel doesn't exist
        """
        channel_id = await self.config.guild(guild).logging_channel()
        return cast(discord.TextChannel, guild.get_channel(channel_id))

    @config.command()
    async def roleadd(self, ctx, sourcerole: discord.Role, targetrole: discord.Role):
        """
        Sets that a given role can manage a given role by applying and removing it
        """
        sourceroleid = str(sourcerole.id)
        targetroleid = str(targetrole.id)
        roles = await self.config.guild(ctx.guild).role_map()
        if sourceroleid in roles:
            if targetroleid not in roles[sourceroleid]:
                roles[sourceroleid].append(targetroleid)
                await self.config.guild(ctx.guild).role_map.set(roles)
                await ctx.send(f"Role {sourcerole} can now manage {targetrole}")
        else:
            roles[sourceroleid] = list()
            roles[sourceroleid].append(targetroleid)
            await self.config.guild(ctx.guild).role_map.set(roles)
            await ctx.send(f"Role {sourcerole} can now manage {targetrole}")

    @config.command()
    async def roledel(self, ctx, sourcerole: discord.Role, targetrole: discord.Role):
        """
        Removes that a given role can manage a given role by applying and removing it
        """
        roles = await self.config.guild(ctx.guild).role_map()
        sourceroleid = str(sourcerole.id)
        targetroleid = str(targetrole.id)
        if sourceroleid in roles:
            if targetroleid in roles[sourceroleid]:
                roles[sourceroleid].remove(targetroleid)
                await self.config.guild(ctx.guild).role_map.set(roles)
                await ctx.send(f"Role {sourcerole} can no longer manage {targetrole}")

    @config.command()
    async def enable(self, ctx):
        """
        Enable the plugin
        """
        try:
            await self.config.guild(ctx.guild).enabled.set(True)
            await ctx.send("The module is now enabled")

        except (ValueError, KeyError, AttributeError):
            await ctx.send("There was a problem enabling the module")

    @rolemanage.command()
    async def remove(self, ctx, user: discord.Member, role: str):
        """
        remove any rolemanage on the targeted user
        """
        enabled = await self.config.guild(ctx.guild).enabled()
        if not enabled:
            await ctx.send("This module is not enabled")
            return

        role = await self.name_to_role(ctx.guild, role)
        if not role:
            await ctx.send("I didn't recognise that role")
            return

        role_map_dict = await self.config.guild(ctx.guild).role_map()
        allowed_roles = set()
        roleid = str(role.id)
        for author_role in ctx.author.roles:
            authorroleid = str(author_role.id)
            if authorroleid in role_map_dict:
                allowed_roles.update(role_map_dict[authorroleid])
                log.debug(f"found role mappings {role_map_dict[authorroleid]}")

        if roleid not in allowed_roles:
            log.debug(f"The {role} was not in the {allowed_roles}")
            await ctx.send("You are not authorised to remove this role")
            return
        reason = f"Role {role} requested to be removed by {ctx.author}"
        try:
            await user.remove_roles(role, reason=reason)
        except Forbidden:
            await self.config.guild(ctx.guild).enabled.set(False)
            await ctx.send("I do not have permission to manage roles in this server")

        await self.send_log_message(
            ctx.guild,
            reason,
            ctx.author,
            user,
            ctx.message.jump_url,
        )
        await ctx.send(f"{role.name} has been removed")

    @rolemanage.command()
    async def apply(self, ctx, user: discord.Member, role: str):
        """
        Apply a role to the targeted user
        """
        enabled = await self.config.guild(ctx.guild).enabled()
        if not enabled:
            await ctx.send("This module is not enabled")
            return

        role = await self.name_to_role(ctx.guild, role)
        if not role:
            await ctx.send("I didn't recognise that role")
            return

        role_map_dict = await self.config.guild(ctx.guild).role_map()
        allowed_roles = set()
        roleid = str(role.id)
        for author_role in ctx.author.roles:
            authorroleid = str(author_role.id)
            if authorroleid in role_map_dict:
                allowed_roles.update(role_map_dict[authorroleid])

        if roleid not in allowed_roles:
            log.debug(f"The {role} was not in the {allowed_roles}")
            await ctx.send("You are not authorised to add this role")
            return

        reason = f"Role {role} requested to be added by {ctx.author}"
        try:
            await user.add_roles(role, reason=reason)
        except Forbidden:
            await self.config.guild(ctx.guild).enabled.set(False)
            await ctx.send("I do not have permission to manage roles in this server")

        await self.send_log_message(
            ctx.guild,
            reason,
            ctx.author,
            user,
            ctx.message.jump_url,
        )
        await ctx.send(f"{role.name} has been added")

    async def name_to_role(self, guild: discord.Guild, name) -> discord.Role:
        names = []
        name2role = {}
        for role in await guild.fetch_roles():
            names.append(role.name)
            name2role[role.name] = role
        match, score = process.extractOne(name, names)
        log.debug(f"{match}, {score}")
        if score < 70:
            return None
        return name2role[match]

    @commands.guild_only()
    @commands.group()
    @checks.mod_or_permissions(administrator=True)
    async def configpunish(self, ctx):
        """
        Configure the punish module
        """
        pass

    @configpunish.command()
    @checks.mod_or_permissions(administrator=True)
    async def memberrole(self, ctx, role: discord.Role):
        """
        Set the member role to be added/removed during punishment
        """
        await self.config.guild(ctx.guild).member_role_id.set(role.id)
        await ctx.send(f"Member role set to {role.name}")

    @configpunish.command()
    @checks.mod_or_permissions(administrator=True)
    async def punishedrole(self, ctx, role: discord.Role):
        """
        Set the punished role to be added/removed during punishment
        """
        await self.config.guild(ctx.guild).punished_role_id.set(role.id)
        await ctx.send(f"Punished role set to {role.name}")

    @commands.command()
    @commands.guild_only()
    @checks.mod_or_permissions(administrator=True)
    async def punish(self, ctx, discord_id: int):
        """
        Punish a user: adds Punished role, removes Member role
        """
        enabled = await self.config.guild(ctx.guild).enabled()
        if not enabled:
            await ctx.send("This module is not enabled")
            return

        user = ctx.guild.get_member(discord_id)
        if user is None:
            await ctx.send("User not found.")
            return

        punished_role_id = await self.config.guild(ctx.guild).punished_role_id()
        member_role_id = await self.config.guild(ctx.guild).member_role_id()
        if punished_role_id is None or member_role_id is None:
            await ctx.send(
                "Punished role or Member role is not set. Please set them using `!configpunish` commands."
            )
            return

        punished_role = ctx.guild.get_role(punished_role_id)
        member_role = ctx.guild.get_role(member_role_id)
        if punished_role is None or member_role is None:
            await ctx.send("Punished role or Member role not found in guild.")
            return

        reason = f"Punished by {ctx.author}"
        try:
            await user.remove_roles(member_role, reason=reason)
            await user.add_roles(punished_role, reason=reason)
        except Forbidden:
            await ctx.send("I do not have permission to manage roles for this user.")
            return

        await self.send_log_message(
            ctx.guild,
            f"User {user} has been punished by {ctx.author}",
            ctx.author,
            user,
            ctx.message.jump_url,
        )
        await ctx.send(f"User {user} has been punished.")

    @commands.command()
    @commands.guild_only()
    @checks.mod_or_permissions(administrator=True)
    async def unpunish(self, ctx, discord_id: int):
        """
        Unpunish a user: removes Punished role, adds Member role.
        """
        enabled = await self.config.guild(ctx.guild).enabled()
        if not enabled:
            await ctx.send("This module is not enabled")
            return

        user = ctx.guild.get_member(discord_id)
        if user is None:
            await ctx.send("User not found.")
            return

        punished_role_id = await self.config.guild(ctx.guild).punished_role_id()
        member_role_id = await self.config.guild(ctx.guild).member_role_id()
        if punished_role_id is None or member_role_id is None:
            await ctx.send(
                "Punished role or Member role is not set. Please set them using `!configpunish` commands."
            )
            return

        punished_role = ctx.guild.get_role(punished_role_id)
        member_role = ctx.guild.get_role(member_role_id)
        if punished_role is None or member_role is None:
            await ctx.send("Punished role or Member role not found in guild.")
            return

        reason = f"Unpunished by {ctx.author}"
        try:
            await user.add_roles(member_role, reason=reason)
            await user.remove_roles(punished_role, reason=reason)
        except Forbidden:
            await ctx.send("I do not have permission to manage roles for this user.")
            return

        await self.send_log_message(
            ctx.guild,
            f"User {user} has been unpunished by {ctx.author}",
            ctx.author,
            user,
            ctx.message.jump_url,
        )
        await ctx.send(f"User {user} has been unpunished.")

    @rolemanage.command()
    async def addroletorole(self, ctx, role_to_add: discord.Role, base_role: discord.Role):
        """
        Add a role to all members who have a specific role.

        Parameters:
        -----------
        role_to_add: The role to add to members
        base_role: Members with this role will get the role_to_add
        
        Example:
        --------
        !rolemanage addroletorole "Age Vetted" Member
        """
        enabled = await self.config.guild(ctx.guild).enabled()
        if not enabled:
            await ctx.send("This module is not enabled")
            return

        try:
            members_modified = 0
            members_skipped = 0
            async with ctx.typing():
                for member in base_role.members:
                    if role_to_add not in member.roles:
                        try:
                            await member.add_roles(role_to_add, reason=f"Mass role addition requested by {ctx.author}")
                            members_modified += 1
                        except discord.Forbidden:
                            members_skipped += 1
                            continue

            result_msg = f"Role addition complete!\nAdded {role_to_add.name} to {members_modified} members who had {base_role.name}\nSkipped {members_skipped} members due to permission issues"
            await ctx.send(result_msg)
            
            # Send to log channel
            await self.send_log_message(
                ctx.guild,
                f"Mass role addition: {result_msg}",
                ctx.author,
                ctx.author,  # No specific target for mass operation
                ctx.message.jump_url,
            )
            log.info(f"User {ctx.author.id} performed mass role addition of {role_to_add.name} to {members_modified} members with {base_role.name}")

        except discord.Forbidden:
            await ctx.send("I don't have permission to manage roles!")
        except Exception as e:
            log.error(f"Error in addroletorole: {str(e)}")
            await ctx.send(f"An error occurred: {str(e)}")

    @rolemanage.command()
    async def removerolefromrole(self, ctx, role_to_remove: discord.Role, base_role: discord.Role):
        """
        Remove a role from all members who have a specific role.

        Parameters:
        -----------
        role_to_remove: The role to remove from members
        base_role: Remove role_to_remove from members who have this role
        
        Example:
        --------
        !rolemanage removerolefromrole "Age Vetted" Member
        """
        enabled = await self.config.guild(ctx.guild).enabled()
        if not enabled:
            await ctx.send("This module is not enabled")
            return

        try:
            members_modified = 0
            members_skipped = 0
            async with ctx.typing():
                for member in base_role.members:
                    if role_to_remove in member.roles:
                        try:
                            await member.remove_roles(role_to_remove, reason=f"Mass role removal requested by {ctx.author}")
                            members_modified += 1
                        except discord.Forbidden:
                            members_skipped += 1
                            continue

            result_msg = f"Role removal complete!\nRemoved {role_to_remove.name} from {members_modified} members who had {base_role.name}\nSkipped {members_skipped} members due to permission issues"
            await ctx.send(result_msg)
            
            # Send to log channel
            await self.send_log_message(
                ctx.guild,
                f"Mass role removal: {result_msg}",
                ctx.author,
                ctx.author,  # No specific target for mass operation
                ctx.message.jump_url,
            )
            log.info(f"User {ctx.author.id} performed mass role removal of {role_to_remove.name} from {members_modified} members with {base_role.name}")

        except discord.Forbidden:
            await ctx.send("I don't have permission to manage roles!")
        except Exception as e:
            log.error(f"Error in removerolefromrole: {str(e)}")
            await ctx.send(f"An error occurred: {str(e)}")
