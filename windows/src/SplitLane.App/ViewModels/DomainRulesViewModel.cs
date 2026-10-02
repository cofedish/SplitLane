using System.Collections.ObjectModel;
using SplitLane.App.Infrastructure;
using SplitLane.Core.Configuration;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;

namespace SplitLane.App.ViewModels;

/// <summary>Destination rules use the same configuration owner and save workflow as application rules.</summary>
public sealed class DomainRulesViewModel : ObservableObject
{
    private readonly MainViewModel _main;

    /// <summary>Builds the destination editor.</summary>
    public DomainRulesViewModel(MainViewModel main)
    {
        _main = main;
        AddCommand = new RelayCommand(() =>
        {
            Rules.Add(new DomainRuleViewModel(new DomainRule { Pattern = "" }, _main.MarkDirty));
            _main.MarkDirty();
        });
        RemoveCommand = new RelayCommand(value =>
        {
            if (value is DomainRuleViewModel row)
            {
                Rules.Remove(row);
                _main.MarkDirty();
            }
        });
    }

    /// <summary>Editable rows.</summary>
    public ObservableCollection<DomainRuleViewModel> Rules { get; } = [];

    /// <summary>Applications already captured by the existing identity picker.</summary>
    public ObservableCollection<DomainApplicationChoice> Applications { get; } = [];

    /// <summary>Adds an unsaved row.</summary>
    public RelayCommand AddCommand { get; }

    /// <summary>Removes one row.</summary>
    public RelayCommand RemoveCommand { get; }

    /// <summary>Reloads the persisted rules.</summary>
    public void LoadFrom(RuntimeConfiguration configuration)
    {
        Rules.Clear();
        foreach (var rule in configuration.DomainRules)
        {
            Rules.Add(new DomainRuleViewModel(rule, _main.MarkDirty));
        }
        RefreshApplications();
    }

    /// <summary>Refreshes selectors without changing existing scope when an application disappears.</summary>
    public void RefreshApplications()
    {
        var choices = _main.Applications.ToRules().Select(r =>
            new DomainApplicationChoice(r.Id, r.Identity.DisplayName)).ToList();
        foreach (var id in Rules.Select(r => r.ProcessRuleId).OfType<string>().Distinct(ExecutablePath.Comparer))
        {
            if (!choices.Any(c => ExecutablePath.Comparer.Equals(c.Id, id)))
            {
                choices.Add(new DomainApplicationChoice(id, "Приложение удалено: " + ExecutablePath.FileName(id)));
            }
        }
        // Keep selected item objects alive. Clearing ItemsSource makes a two-way ComboBox write
        // null back, silently widening an application-scoped rule to all applications.
        if (Applications.Count == 0)
        {
            Applications.Add(new DomainApplicationChoice(null, "Все приложения"));
        }
        foreach (var choice in choices)
        {
            var existing = Applications.FirstOrDefault(c => ExecutablePath.Comparer.Equals(c.Id, choice.Id));
            if (existing is null)
            {
                Applications.Add(choice);
            }
            else
            {
                existing.Label = choice.Label;
            }
        }
        foreach (var obsolete in Applications.Where(c => c.Id is not null &&
                     !choices.Any(choice => ExecutablePath.Comparer.Equals(choice.Id, c.Id))).ToArray())
        {
            Applications.Remove(obsolete);
        }
    }

    /// <summary>Rebinds scopes when the existing application editor reselects or migrates an identity.</summary>
    public void Rebind(string before, string after)
    {
        foreach (var row in Rules.Where(r => ExecutablePath.Comparer.Equals(r.ProcessRuleId, before)))
        {
            row.ProcessRuleId = after;
        }
    }

    /// <summary>Collects validated rows for the existing save command.</summary>
    public IReadOnlyList<DomainRule> ToRules() => Rules.Select(row => row.ToRule()).ToArray();
}

/// <summary>A selector item; null means all applications.</summary>
public sealed class DomainApplicationChoice(string? id, string label) : ObservableObject
{
    private string _label = label;

    /// <summary>Stable selector identity.</summary>
    public string? Id { get; } = id;

    /// <summary>Display label updated without replacing a selected item.</summary>
    public string Label
    {
        get => _label;
        set => Set(ref _label, value);
    }
}

/// <summary>One editable destination policy.</summary>
public sealed class DomainRuleViewModel : ObservableObject
{
    private readonly Action _changed;
    private DomainRule _rule;

    /// <summary>Wraps the stored rule without dropping advanced selectors.</summary>
    public DomainRuleViewModel(DomainRule rule, Action changed)
    {
        _rule = rule;
        _changed = changed;
    }

    /// <summary>Exact name or wildcard.</summary>
    public string Pattern
    {
        get => _rule.Pattern;
        set { _rule = _rule with { Pattern = value }; Changed(); Raise(nameof(Error)); }
    }

    /// <summary>The policy action.</summary>
    public RouteAction Action
    {
        get => _rule.Action;
        set { _rule = _rule with { Action = value }; Changed(); }
    }

    /// <summary>Whether this row participates in routing.</summary>
    public bool IsEnabled
    {
        get => _rule.IsEnabled;
        set { _rule = _rule with { IsEnabled = value }; Changed(); }
    }

    /// <summary>Existing verified application selector, or null for all applications.</summary>
    public string? ProcessRuleId
    {
        get => _rule.ProcessRuleId;
        set { _rule = _rule with { ProcessRuleId = value }; Changed(); }
    }

    /// <summary>Visible validation, before Save.</summary>
    public string Error => DomainPattern.TryParse(Pattern, out _, out _)
        ? string.Empty : "Укажите имя домена или *.example.com. Wildcard не включает example.com.";

    /// <summary>Normalizes valid patterns and refuses malformed rows.</summary>
    public DomainRule ToRule()
    {
        if (!DomainPattern.TryParse(Pattern, out var pattern, out _))
        {
            throw new ConfigurationValidationException(ConfigurationValidationCode.InvalidDomainRule, Error);
        }
        return _rule with { Pattern = pattern.Normalized };
    }

    private void Changed([System.Runtime.CompilerServices.CallerMemberName] string? name = null)
    {
        Raise(name);
        _changed();
    }
}
