# ffxiv-exdgetters.py
#
# Automagically labels most exd getter functions along with a hint indicating which sheet/sheet id its fetching from
#

import idaapi

# nb: "pattern": "func suffix" OR None
exd_func_patterns = {
    "48 83 EC 28 48 8B 05 ? ? ? ? 44 8B C1 BA ? ? ? ? 48 8B 88 ? ? ? ? E8 ? ? ? ? 48 85 C0 75 05 48 83 C4 28 C3 48 8B 00 48 83 C4 28 C3": None,
    "48 83 EC 28 48 8B 05 ? ? ? ? BA ? ? ? ? 44 0F B6 C1 48 8B 88 ? ? ? ? E8 ? ? ? ? 48 85 C0 75 05 48 83 C4 28 C3 48 8B 00 48 83 C4 28 C3": None,
    "48 83 EC 28 48 8B 05 ? ? ? ? 44 8D 81 ? ? ? ? BA ? ? ? ? 48 8B 88 ? ? ? ? E8 ? ? ? ? 48 85 C0 75 05 48 83 C4 28 C3 48 8B 00 48 83 C4 28 C3": None,
    "48 83 EC 38 48 8B 05 ? ? ? ? 44 8B CA 44 8B C1 48 C7 44 24 ? ? ? ? ? BA ? ? ? ? 48 C7 44 24 ? ? ? ? ? 48 8B 88 ? ? ? ? E8 ? ? ? ? 48 85 C0 75 05 48 83 C4 38 C3 48 8B 00 48 83 C4 38 C3": None,
    "48 83 EC 28 48 8B 05 ? ? ? ? BA ? ? ? ? 48 8B 88 ? ? ? ? E8 ? ? ? ? 48 85 C0 74 14 48 8B 10 48 8B C8 FF 52 08 84 C0 75 07 B0 01 48 83 C4 28 C3 32 C0 48 83 C4 28 C3": None,
    "48 83 EC 28 85 C9 74 20 48 8B 05 ? ? ? ? 44 8B C1 BA ? ? ? ? 48 8B 88 ? ? ? ? E8 ? ? ? ? 48 85 C0 75 07 33 C0 48 83 C4 28 C3 48 8B 00 48 83 C4 28 C3": None,
    "48 83 EC 28 48 8B 05 ? ? ? ? 44 8B C1 BA ? ? ? ? 48 8B 88 ? ? ? ? E8 ? ? ? ? 48 85 C0 74 17 48 8B 08 48 85 C9 74 0F 8B 01 25 ? ? ? ? 48 03 C1 48 83 C4 28 C3 33 C0 48 83 C4 28 C3": None,

    # unsure if this is totally accurate but it looks to be the case
    "48 8B 05 ? ? ? ? BA ? ? ? ? 48 8B 88 ? ? ? ? E9 ? ? ? ?": "::rowCount"
}

# todo: figure out how/where these exd getters are used
# .text:0000000140622200                         sub_140622200   proc near               ; CODE XREF: sub_14067D8E0+D3
# .text:0000000140622200 48 8B 05 F1 7F 46 01                    mov     rax, cs:qword_141A8A1F8
# .text:0000000140622207 BA 59 01 00 00                          mov     edx, 159h
# .text:000000014062220C 48 8B 88 E8 2B 00 00                    mov     rcx, [rax+2BE8h]
# .text:0000000140622213 E9 28 E2 E2 FF                          jmp     sub_140450440
# .text:0000000140622213                         sub_140622200   endp

exd_map = {
    209: "Achievement",
    210: "AchievementCategory",
    211: "AchievementKind",
    4: "Action",
    656: "ActionCastTimeline",
    624: "ActionCastVFX",
    3: "ActionCategory",
    642: "ActionComboRoute",
    651: "ActionComboRouteTransient",
    431: "ActionIndirection",
    751: "ActionInit",
    613: "ActionParam",
    430: "ActionProcStatus",
    100: "ActionTimeline",
    709: "ActionTimelineMove",
    608: "ActionTimelineReplace",
    568: "ActionTransient",
    646: "ActivityFeedButtons",
    619: "ActivityFeedCaptions",
    620: "ActivityFeedGroupCaptions",
    618: "ActivityFeedImages",
    0: "Addon",
    251: "AddonHud",
    640: "AddonHudLayout",
    667: "AddonHudSize",
    731: "AddonLayout",
    250: "AddonParam",
    596: "AddonTalkParam",
    402: "AddonTransient",
    316: "Adventure",
    648: "AdventureExPhase",
    452: "AetherCurrent",
    440: "AetherCurrentCompFlgSet",
    357: "AetherialWheel",
    252: "Aetheryte",
    253: "AetheryteSystemDefine",
    409: "AirshipExplorationLevel",
    412: "AirshipExplorationLog",
    437: "AirshipExplorationParamType",
    408: "AirshipExplorationPart",
    410: "AirshipExplorationPoint",
    487: "AirshipSkyIsland",
    242: "AnimationLOD",
    532: "AnimaWeapon5",
    530: "AnimaWeapon5Param",
    525: "AnimaWeapon5PatternGroup",
    545: "AnimaWeapon5SpiritTalk",
    548: "AnimaWeapon5SpiritTalkParam",
    544: "AnimaWeapon5SpiritTalkType",
    524: "AnimaWeapon5TradeItem",
    57: "AnimaWeaponFUITalk",
    200: "AnimaWeaponFUITalkParam",
    531: "AnimaWeaponIcon",
    533: "AnimaWeaponItem",
    734: "AozAction",
    747: "AozActionTransient",
    766: "AOZArrangement",
    767: "AOZBoss",
    763: "AOZContent",
    765: "AOZContentBriefingBNpc",
    761: "AOZScore",
    777: "AOZWeeklyReward",
    561: "AquariumFish",
    560: "AquariumWater",
    61: "ArrayEventHandler",
    101: "AttackType",
    64: "Attributive",
    605: "BacklightColor",
    270: "Ballista",
    6: "Balloon",
    234: "BaseParam",
    63: "Battalion",
    77: "BattleLeve",
    79: "BattleLeveRule",
    511: "BeastRankBonus",
    284: "BeastReputationRank",
    285: "BeastTribe",
    7: "Behavior",
    8: "BehaviorPath",
    662: "BgcArmyAction",
    664: "BgcArmyActionTransient",
    134: "BGM",
    137: "BGMFade",
    138: "BGMFadeType",
    135: "BGMScene",
    136: "BGMSituation",
    672: "BGMSwitch",
    139: "BGMSystemDefine",
    629: "BNpcAnnounceIcon",
    46: "BNpcBase",
    48: "BNpcCustomize",
    47: "BNpcName",
    49: "BNpcParts",
    50: "BNpcState",
    230: "Buddy",
    228: "BuddyAction",
    229: "BuddyEquip",
    233: "BuddyItem",
    231: "BuddyRank",
    232: "BuddySkill",
    243: "Cabinet",
    631: "CabinetCategory",
    161: "Calendar",
    282: "Carry",
    266: "Channeling",
    175: "CharaMakeClassEquip",
    177: "CharaMakeCustomize",
    176: "CharaMakeName",
    174: "CharaMakeType",
    362: "ChocoboRace",
    354: "ChocoboRaceAbility",
    353: "ChocoboRaceAbilityType",
    365: "ChocoboRaceCalculateParam",
    497: "ChocoboRaceChallenge",
    355: "ChocoboRaceItem",
    369: "ChocoboRaceRank",
    397: "ChocoboRaceRanking",
    370: "ChocoboRaceStatus",
    371: "ChocoboRaceTerritory",
    356: "ChocoboRaceTutorial",
    396: "ChocoboRaceWeather",
    202: "ChocoboTaxi",
    203: "ChocoboTaxiStand",
    59: "ClassJob",
    60: "ClassJobCategory",
    454: "ClassJobResident",
    553: "ColorFilter",
    570: "Colosseum",
    495: "ColosseumMatchRank",
    172: "Companion",
    173: "CompanionMove",
    455: "CompanionTransient",
    264: "CompanyAction",
    429: "CompanyCraftDraft",
    425: "CompanyCraftDraftCategory",
    448: "CompanyCraftManufactoryState",
    423: "CompanyCraftPart",
    422: "CompanyCraftProcess",
    400: "CompanyCraftSequence",
    449: "CompanyCraftSupplyItem",
    428: "CompanyCraftType",
    91: "CompanyLeve",
    92: "CompanyLeveRule",
    333: "CompleteJournal",
    334: "CompleteJournalCategory",
    66: "Completion",
    700: "Condition",
    103: "ConfigKey",
    638: "ContentAttributeRect",
    718: "ContentCloseCycle",
    652: "ContentDirectorManagedSG",
    695: "ContentEffectiveTime",
    704: "ContentEntry",
    601: "ContentExAction",
    476: "ContentFinderCondition",
    555: "ContentFinderConditionTransient",
    615: "ContentGauge",
    616: "ContentGaugeColor",
    475: "ContentMemberType",
    151: "ContentNpcTalk",
    671: "ContentRewardCondition",
    153: "ContentRoulette",
    707: "ContentRouletteOpenRule",
    670: "ContentRouletteRoleBonus",
    289: "ContentsNote",
    290: "ContentsNoteCategory",
    291: "ContentsNoteLevel",
    725: "ContentsNoteRewardEurekaEXP",
    149: "ContentTalk",
    150: "ContentTalkParam",
    292: "ContentType",
    509: "ContentUICategory",
    54: "CraftAction",
    78: "CraftLeve",
    80: "CraftLeveTalk",
    52: "CraftType",
    445: "Credit",
    769: "CreditBackImage",
    446: "CreditCast",
    776: "CreditDataSet",
    770: "CreditFont",
    773: "CreditList",
    775: "CreditListText",
    787: "CreditVersion",
    416: "Currency",
    417: "CurrencyLimit",
    114: "CustomTalk",
    758: "CustomTalkDynamicIcon",
    781: "CustomTalkNestHandlers",
    128: "Cutscene",
    414: "CutsceneActorSize",
    439: "CutsceneEventMotion",
    184: "CutsceneMotion",
    733: "CutsceneName",
    129: "CutsceneWorkIndex",
    288: "CutScreenImage",
    286: "CycleTime",
    317: "DailySupplyItem",
    541: "DeepDungeon",
    546: "DeepDungeonBan",
    547: "DeepDungeonDanger",
    540: "DeepDungeonEquipment",
    549: "DeepDungeonFloorEffectUI",
    550: "DeepDungeonGrowData",
    539: "DeepDungeonItem",
    534: "DeepDungeonLayer",
    714: "DeepDungeonMagicStone",
    518: "DeepDungeonMap5X",
    515: "DeepDungeonRoom",
    543: "DeepDungeonStatus",
    113: "DefaultTalk",
    180: "DefaultTalkLipSyncType",
    35: "DeliveryQuest",
    720: "Description",
    713: "DescriptionPage",
    712: "DescriptionSection",
    729: "DescriptionString",
    323: "DirectorSystemDefine",
    324: "DirectorType",
    577: "DisposalShop",
    576: "DisposalShopFilterType",
    578: "DisposalShopItem",
    724: "DomaStoryProgress",
    492: "DpsChallenge",
    491: "DpsChallengeOfficer",
    581: "DpsChallengeTransient",
    752: "EmjAddon",
    762: "EmjCharaViewCamera",
    778: "EmjDani",
    181: "Emote",
    183: "EmoteCategory",
    182: "EmoteMode",
    97: "ENpcBase",
    784: "ENpcDressUp",
    783: "ENpcDressUpDress",
    96: "ENpcResident",
    106: "EObj",
    563: "EObjName",
    645: "EquipRaceCategory",
    14: "EquipSlotCategory",
    68: "Error",
    723: "Eureka",
    722: "EurekaAetherItem",
    708: "EurekaAethernet",
    782: "EurekaDungeonPortal",
    705: "EurekaGrowData",
    748: "EurekaLogosMixerProbability",
    742: "EurekaMagiaAction",
    744: "EurekaMagiciteItem",
    743: "EurekaMagiciteItemType",
    706: "EurekaSphereElementAdjust",
    710: "EurekaStoryProgress",
    123: "EventAction",
    126: "EventIconPriority",
    127: "EventIconType",
    124: "EventItem",
    464: "EventItemCastTimeline",
    512: "EventItemCategory",
    564: "EventItemHelp",
    465: "EventItemTimeline",
    125: "EventSystemDefine",
    573: "EventVfx",
    692: "ExHotbarCrossbarIndexType",
    155: "ExportedSG",
    574: "ExtraCommand",
    419: "ExVersion",
    699: "FashionCheckThemeCategory",
    701: "FashionCheckWeeklyTheme",
    164: "Fate",
    165: "FateEvent",
    214: "FCActivity",
    224: "FCActivityCategory",
    215: "FCAuthority",
    217: "FCAuthorityCategory",
    221: "FCChestName",
    223: "FCCrestSymbol",
    421: "FccShop",
    222: "FCDefine",
    216: "FCHierarchy",
    225: "FCProfile",
    218: "FCRank",
    219: "FCReputation",
    220: "FCRights",
    262: "Festival",
    296: "FieldMarker",
    249: "FishingRecordType",
    636: "FishingRecordTypeTransient",
    246: "FishingSpot",
    247: "FishParameter",
    406: "Frontline",
    208: "Frontline01",
    373: "Frontline02",
    424: "Frontline03",
    527: "Frontline04",
    293: "GardeningSeed",
    28: "GatheringCondition",
    25: "GatheringExp",
    21: "GatheringItem",
    413: "GatheringItemLevelConvertTable",
    335: "GatheringItemPoint",
    88: "GatheringLeve",
    90: "GatheringLeveBNpcEntry",
    89: "GatheringLeveRoute",
    87: "GatheringLeveRule",
    29: "GatheringNotebook",
    336: "GatheringNotebookList",
    24: "GatheringPoint",
    22: "GatheringPointBase",
    447: "GatheringPointBonus",
    23: "GatheringPointBonusType",
    27: "GatheringPointName",
    442: "GatheringSubCategory",
    26: "GatheringType",
    554: "GcArmyCandidateCategory",
    660: "GcArmyCapture",
    668: "GcArmyCaptureTactics",
    669: "GcArmyEquipPreset",
    519: "GcArmyExpedition",
    520: "GcArmyExpeditionMemberBonus",
    521: "GcArmyExpeditionTrait",
    522: "GcArmyExpeditionTraitCond",
    529: "GcArmyExpeditionType",
    280: "GcArmyMember",
    542: "GcArmyMemberGrow",
    537: "GcArmyMemberGrowExp",
    516: "GcArmyProgress",
    517: "GcArmyTraining",
    190: "GCRankGridaniaFemaleText",
    189: "GCRankGridaniaMaleText",
    188: "GCRankLimsaFemaleText",
    187: "GCRankLimsaMaleText",
    192: "GCRankUldahFemaleText",
    191: "GCRankUldahMaleText",
    485: "GCScripShopCategory",
    486: "GCScripShopItem",
    196: "GCShop",
    194: "GCShopItemCategory",
    199: "GCSupplyDefine",
    197: "GCSupplyDuty",
    198: "GCSupplyDutyReward",
    104: "GeneralAction",
    388: "GFATE",
    361: "GFateClimbing",
    738: "GFateClimbing2",
    746: "GFateClimbing2Content",
    741: "GFateClimbing2TotemType",
    377: "GFateDance",
    364: "GFateHiddenObject",
    760: "GFateRideShooting",
    378: "GFateRoulette",
    372: "GFateStelth",
    603: "GilShop",
    736: "GilShopInfo",
    602: "GilShopItem",
    120: "GimmickAccessor",
    119: "GimmickBill",
    314: "GimmickJump",
    121: "GimmickRect",
    122: "GimmickYesNo",
    346: "GoldSaucerArcadeMachine",
    556: "GoldSaucerContent",
    327: "GoldSaucerTalk",
    366: "GoldSaucerTextData",
    186: "GrandCompany",
    193: "GrandCompanyRank",
    575: "GroupPoseCharaStatus",
    185: "GuardianDeity",
    76: "GuildleveAssignment",
    75: "GuildleveAssignmentCategory",
    85: "GuildleveAssignmentTalk",
    72: "GuildleveEvaluation",
    146: "GuildOrder",
    147: "GuildOrderGuide",
    148: "GuildOrderOfficer",
    287: "HairMakeType",
    461: "HouseRetainerPose",
    635: "HousingAethernet",
    740: "HousingAppeal",
    678: "HousingEmploymentNpcList",
    676: "HousingEmploymentNpcRace",
    272: "HousingExterior",
    277: "HousingFurniture",
    273: "HousingInterior",
    279: "HousingLandSet",
    569: "HousingMapMarkerInfo",
    469: "HousingMateAuthority",
    737: "HousingMerchantPose",
    719: "HousingPileLimit",
    471: "HousingPlacement",
    276: "HousingPreset",
    426: "HousingUnitedExterior",
    513: "HousingUnplacement",
    275: "HousingYardObject",
    140: "HowTo",
    142: "HowToCategory",
    141: "HowToPage",
    143: "InstanceContent",
    154: "InstanceContentBuff",
    785: "InstanceContentCSBonus",
    152: "InstanceContentGuide",
    528: "InstanceContentRewardItem",
    145: "InstanceContentTextData",
    144: "InstanceContentType",
    10: "Item",
    16: "ItemAction",
    11: "ItemFood",
    17: "ItemLevel",
    9: "ItemSearchCategory",
    12: "ItemSeries",
    13: "ItemSpecialBonus",
    15: "ItemUICategory",
    265: "Jingle",
    162: "JournalCategory",
    163: "JournalGenre",
    503: "JournalSection",
    5: "Knockback",
    33: "LegacyQuest",
    73: "Leve",
    71: "LeveAssignmentType",
    74: "LeveClient",
    168: "Level",
    81: "LeveRewardItem",
    82: "LeveRewardItemGroup",
    86: "LeveString",
    83: "LeveSystemDefine",
    84: "LeveVfx",
    1: "LinkRace",
    663: "LoadingImage",
    348: "LoadingTips",
    349: "LoadingTipsSub",
    62: "Lobby",
    294: "Lockon",
    160: "LogFilter",
    157: "LogKind",
    159: "LogKindCategoryText",
    158: "LogMessage",
    715: "LootModeType",
    579: "LotteryExchangeShop",
    263: "MacroIcon",
    340: "MacroIconRedirectOld",
    239: "MainCommand",
    240: "MainCommandCategory",
    674: "Maneuvers",
    673: "ManeuversArmor",
    107: "Map",
    108: "MapMarker",
    630: "MapMarkerRegion",
    109: "MapSymbol",
    95: "Marker",
    443: "MasterpieceSupplyDuty",
    617: "MasterpieceSupplyMultiplier",
    470: "MateAuthorityCategory",
    19: "Materia",
    18: "MateriaJoinRate",
    562: "MateriaParam",
    20: "MateriaTomestoneRate",
    749: "MiniGameRA",
    750: "MiniGameRANotes",
    479: "MinionRace",
    473: "MinionRules",
    484: "MinionSkillType",
    436: "MinionStage",
    434: "MobHuntOrder",
    611: "MobHuntOrderType",
    435: "MobHuntReward",
    415: "MobHuntRewardCap",
    320: "MobHuntTarget",
    687: "ModelAttribute",
    38: "ModelChara",
    689: "ModelScale",
    39: "ModelSkeleton",
    693: "ModelState",
    212: "MonsterNote",
    213: "MonsterNoteTarget",
    110: "MotionTimeline",
    112: "MotionTimelineAdvanceBlend",
    111: "MotionTimelineBlendTable",
    133: "Mount",
    418: "MountAction",
    698: "MountCustomize",
    404: "MountFlyingCondition",
    641: "MountSpeed",
    463: "MountTransient",
    331: "MoveControl",
    523: "MoveTimeline",
    587: "MoveVfx",
    258: "MovieSubtitle",
    259: "MovieSubtitleVoyage",
    69: "NotebookDivision",
    786: "NotebookDivisionCategory",
    102: "NotebookList",
    607: "NotoriousMonster",
    606: "NotoriousMonsterTerritory",
    204: "NpcEquip",
    179: "NpcYell",
    238: "Omen",
    156: "OnlineStatus",
    226: "Opening",
    227: "OpeningSystemDefine",
    499: "Orchestrion",
    505: "OrchestrionCategory",
    504: "OrchestrionPath",
    506: "OrchestrionUiparam",
    169: "ParamGrow",
    481: "PartyContent",
    480: "PartyContentCutscene",
    483: "PartyContentTextData",
    490: "PartyContentTransient",
    321: "PatchMark",
    679: "Perform",
    680: "PerformTransient",
    330: "Permission",
    260: "Pet",
    261: "PetAction",
    30: "PetMirage",
    255: "PhysicsGroup",
    256: "PhysicsOffGroup",
    257: "PhysicsWind",
    582: "Picture",
    585: "PictureCategory",
    99: "PlaceName",
    508: "PlantPotFlowerSeed",
    717: "PreHandler",
    117: "PresetCamera",
    241: "PresetCameraAdjust",
    166: "PublicContent",
    339: "PublicContentCutscene",
    167: "PublicContentTextData",
    450: "Purify",
    205: "PvPAction",
    643: "PvPActionSort",
    647: "PvPInitialSelectActionTrait",
    206: "PvPRank",
    468: "PvPRankTransient",
    639: "PvPSelectTrait",
    655: "PvPSelectTraitTransient",
    207: "PvPTrait",
    622: "QTE",
    32: "Quest",
    170: "QuestBattle",
    171: "QuestBattleSystemDefine",
    474: "QuestClassJobReward",
    711: "QuestClassJobSupply",
    494: "QuestEquipModel",
    34: "QuestRepeatFlag",
    432: "QuestRewardOther",
    31: "QuestSystemDefine",
    593: "QuickChat",
    594: "QuickChatTransient",
    178: "Race",
    385: "RacingChocoboGrade",
    363: "RacingChocoboItem",
    375: "RacingChocoboName",
    382: "RacingChocoboNameCategory",
    384: "RacingChocoboNameInfo",
    379: "RacingChocoboParam",
    105: "RecastNavimesh",
    51: "Recipe",
    55: "RecipeElement",
    56: "RecipeLevelTable",
    332: "RecipeNotebookList",
    269: "RecommendContents",
    306: "Relic",
    310: "Relic3",
    311: "Relic3Materia",
    312: "Relic3Rate",
    313: "Relic3RatePattern",
    394: "Relic6Magicite",
    344: "RelicItem",
    305: "RelicMateria",
    307: "RelicNote",
    309: "RelicNoteCategory",
    325: "Resident",
    586: "ResidentMotionType",
    297: "RetainerTask",
    298: "RetainerTaskLvRange",
    299: "RetainerTaskNormal",
    302: "RetainerTaskParameter",
    552: "RetainerTaskParameterLvDiff",
    301: "RetainerTaskRandom",
    768: "RideShooting",
    753: "RideShootingScheduler",
    756: "RideShootingTarget",
    755: "RideShootingTargetScheduler",
    757: "RideShootingTargetType",
    759: "RideShootingTextData",
    130: "Role",
    716: "RPParameter",
    661: "Salvage",
    591: "SatisfactionNpc",
    590: "SatisfactionSupply",
    592: "SatisfactionSupplyReward",
    666: "SatisfactionSupplyRewardExp",
    612: "ScenarioTree",
    614: "ScenarioTreeTips",
    690: "ScenarioTreeTipsClassQuest",
    688: "ScenarioTreeTipsQuest",
    659: "ScenarioType",
    322: "ScreenImage",
    131: "SE",
    653: "SEBattle",
    466: "SecretRecipeBook",
    565: "SkyIsland",
    588: "SkyIsland2",
    584: "SkyIsland2Mission",
    583: "SkyIsland2MissionDetail",
    598: "SkyIsland2MissionType",
    595: "SkyIsland2RangeType",
    489: "SkyIslandMapMarker",
    488: "SkyIslandSubject",
    621: "Snipe",
    623: "SnipeCollision",
    633: "SnipeElementId",
    697: "SnipeHitEvent",
    625: "SnipePerformanceCamera",
    628: "SpearfishingEcology",
    610: "SpearfishingItem",
    634: "SpearfishingNotebook",
    637: "SpearfishingRecordPage",
    267: "SpecialShop",
    268: "SpecialShopItemCategory",
    526: "Spectator",
    271: "Stain",
    472: "StainTransient",
    70: "Status",
    451: "StatusHitEffect",
    599: "StatusLoopVFX",
    244: "Story",
    245: "StorySystemDefine",
    683: "SubmarineExploration",
    694: "SubmarineExplorationLog",
    684: "SubmarinePart",
    685: "SubmarineRank",
    682: "SubmarineSpecCategory",
    304: "SwitchTalk",
    53: "TerritoryChatRule",
    93: "TerritoryIntendedUse",
    94: "TerritoryType",
    498: "TerritoryTypeTransient",
    65: "TextCommand",
    67: "TextCommandParam",
    116: "Title",
    644: "TomestoneConvert",
    303: "Tomestones",
    571: "TomestonesItem",
    507: "TopicSelect",
    42: "Town",
    98: "Trait",
    345: "TraitRecast",
    467: "TraitTransient",
    315: "Transformation",
    36: "Treasure",
    403: "TreasureHuntRank",
    405: "TreasureHuntTexture",
    37: "TreasureModel",
    283: "TreasureSpot",
    58: "Tribe",
    352: "TripleTriad",
    347: "TripleTriadCard",
    392: "TripleTriadCardRarity",
    395: "TripleTriadCardResident",
    374: "TripleTriadCardType",
    390: "TripleTriadCompetition",
    391: "TripleTriadDefine",
    387: "TripleTriadResident",
    360: "TripleTriadRule",
    493: "Tutorial",
    502: "TutorialDPS",
    501: "TutorialHealer",
    500: "TutorialTank",
    735: "UIColor",
    535: "Vase",
    510: "VaseFlower",
    118: "VFX",
    235: "Warp",
    236: "WarpCondition",
    237: "WarpLogic",
    115: "WeaponTimeline",
    43: "Weather",
    45: "WeatherGroup",
    44: "WeatherRate",
    626: "WeatherReportReplace",
    343: "WeddingBGM",
    342: "WeddingFlowerColor",
    341: "WeddingPlan",
    558: "WeeklyBingoOrderData",
    559: "WeeklyBingoRewardData",
    557: "WeeklyBingoText",
    368: "WeeklyLotBonus",
    367: "WeeklyLotBonusThreshold",
    328: "World",
    329: "WorldDCGroupType",
    696: "XPVPGroupActivity",
    514: "YKW",
    441: "ZoneSharedGroup",
    433: "ZoneTimeline"
}

def do_pattern(pattern, suffix = ""):
    ea = 0

    while True:
        ea = FindBinary(ea + 1, SEARCH_DOWN, pattern)

        if ea == 0xFFFFFFFFFFFFFFFF:
            break

        # this is mega retarded but it works rofl
        ins = FindBinary(ea, SEARCH_DOWN, "BA ? ? ? ?")
        sheetIdx = idc.Dword(ins + 1)

        origName = GetFunctionName(ea)

        # don't rename any funcs that are already named
        if origName[0:4] != "sub_":
            sheetName = exd_map[sheetIdx]

            if suffix == None:
                suffix = ""

            fnName = "Client::ExdData::get%s%s" % (exd_map[sheetIdx], suffix)

            print("found unnamed exd func @ %x -> mapped to %s (%i)" % (ea, sheetName, sheetIdx))

            MakeName(ea, fnName)
            MakeComm(ins, "Sheet: %s (%i)" % (sheetName, sheetIdx))


def run():
    # todo: this doesnt find all getters, there's a few slightly different ones
    # along with others that call different virts in slightly different ways/different args
    for pattern, suffix in exd_func_patterns.items():
        do_pattern(pattern, suffix)


class ffxiv_exdgetters_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL

    wanted_name = "FFXIV - Annotate EXD Getters"
    wanted_hotkey = ""

    comment = 'Automagically names EXD getter funcs'
    help = 'no'
 
    def init(self):
        return idaapi.PLUGIN_OK
 
    def run(self, arg):
        run()
 
    def term(self):
        pass
 
def PLUGIN_ENTRY():
    return ffxiv_exdgetters_t()